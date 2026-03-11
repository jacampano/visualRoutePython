import errno
import csv
import json
import socket
import sys
import time
from datetime import datetime
from html import escape
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import requests
from PySide6.QtCore import QThread, Signal, Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtWebEngineWidgets import QWebEngineView


@dataclass
class HopInfo:
    hop: int
    ip: str
    rtts_ms: List[float]
    hostname: str = ""
    city: str = ""
    country: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    asname: str = ""
    reverse_dns: str = ""
    mobile: bool = False
    proxy: bool = False
    hosting: bool = False
    network_type: str = ""
    lat: Optional[float] = None
    lon: Optional[float] = None

    @property
    def avg_rtt(self) -> Optional[float]:
        return sum(self.rtts_ms) / len(self.rtts_ms) if self.rtts_ms else None


class TracerouteWorker(QThread):
    hop_found = Signal(object)
    finished_ok = Signal(list)
    failed = Signal(str)

    def __init__(
        self,
        target_ip: str,
        ip_mode: str = "auto",
        max_hops: int = 25,
        timeout_s: int = 2,
    ) -> None:
        super().__init__()
        self.target_ip = target_ip.strip()
        self.ip_mode = ip_mode
        self.max_hops = max_hops
        self.timeout_s = timeout_s

    def run(self) -> None:
        try:
            destination_ip, family = self._resolve_target(self.target_ip, self.ip_mode)
        except ValueError as exc:
            self.failed.emit(str(exc))
            return
        except socket.gaierror:
            self.failed.emit("No se pudo resolver la IP/host de destino.")
            return

        try:
            if family == socket.AF_INET6:
                hops = self._run_traceroute_ipv6(destination_ip)
            else:
                hops = self._run_traceroute(destination_ip)
        except PermissionError:
            self.failed.emit(
                "La traza requiere permisos de administrador/root para sockets ICMP."
            )
            return
        except Exception as exc:
            self.failed.emit(f"Traceroute interno falló: {exc}")
            return

        if not hops:
            self.failed.emit("No se obtuvieron saltos.")
            return

        enriched: List[HopInfo] = []
        for hop in hops:
            if hop.ip != "*":
                geo = self._geolocate(hop.ip)
                if geo:
                    hop.city = geo.get("city", "")
                    hop.country = geo.get("country", "")
                    hop.isp = geo.get("isp", "")
                    hop.org = geo.get("org", "")
                    hop.asn = geo.get("as", "")
                    hop.asname = geo.get("asname", "")
                    hop.reverse_dns = geo.get("reverse", "")
                    hop.mobile = bool(geo.get("mobile", False))
                    hop.proxy = bool(geo.get("proxy", False))
                    hop.hosting = bool(geo.get("hosting", False))
                    hop.network_type = self._network_type_from_flags(
                        hop.mobile, hop.proxy, hop.hosting
                    )
                    hop.lat = geo.get("lat")
                    hop.lon = geo.get("lon")
            enriched.append(hop)
            self.hop_found.emit(hop)

        self.finished_ok.emit(enriched)

    @staticmethod
    def _resolve_target(target: str, ip_mode: str) -> tuple[str, int]:
        family = socket.AF_UNSPEC
        if ip_mode == "ipv4":
            family = socket.AF_INET
        elif ip_mode == "ipv6":
            family = socket.AF_INET6
        info = socket.getaddrinfo(target, None, family, socket.SOCK_DGRAM)
        if not info:
            raise ValueError("No se pudo resolver el destino.")
        selected = info[0]
        addr_family = selected[0]
        sockaddr = selected[4]
        ip = sockaddr[0]
        return ip, addr_family

    def _run_traceroute(self, destination_ip: str) -> List[HopInfo]:
        hops: List[HopInfo] = []
        port = 33434
        probes_per_hop = 3

        for ttl in range(1, self.max_hops + 1):
            rtts: List[float] = []
            hop_ip = "*"
            reached_destination = False

            for _ in range(probes_per_hop):
                rtt, responder_ip, is_destination = self._probe(destination_ip, ttl, port)
                port += 1

                if responder_ip and hop_ip == "*":
                    hop_ip = responder_ip
                if rtt is not None:
                    rtts.append(rtt)
                if is_destination:
                    reached_destination = True

            hostname = ""
            if hop_ip != "*":
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0]
                except socket.herror:
                    hostname = ""

            hop = HopInfo(hop=ttl, ip=hop_ip, rtts_ms=rtts, hostname=hostname)
            hops.append(hop)

            if reached_destination or hop_ip == destination_ip:
                break

        return hops

    def _run_traceroute_ipv6(self, destination_ip: str) -> List[HopInfo]:
        hops: List[HopInfo] = []
        port = 33434
        probes_per_hop = 3

        for ttl in range(1, self.max_hops + 1):
            rtts: List[float] = []
            hop_ip = "*"
            reached_destination = False

            for _ in range(probes_per_hop):
                rtt, responder_ip, is_destination = self._probe_ipv6(destination_ip, ttl, port)
                port += 1

                if responder_ip and hop_ip == "*":
                    hop_ip = responder_ip
                if rtt is not None:
                    rtts.append(rtt)
                if is_destination:
                    reached_destination = True

            hostname = ""
            if hop_ip != "*":
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0]
                except socket.herror:
                    hostname = ""

            hop = HopInfo(hop=ttl, ip=hop_ip, rtts_ms=rtts, hostname=hostname)
            hops.append(hop)

            if reached_destination or hop_ip == destination_ip:
                break

        return hops

    def _probe(self, destination_ip: str, ttl: int, port: int) -> tuple[Optional[float], Optional[str], bool]:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        try:
            recv_sock.settimeout(self.timeout_s)
            recv_sock.bind(("", port))
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            start = time.perf_counter()
            send_sock.sendto(b"", (destination_ip, port))

            try:
                packet, addr = recv_sock.recvfrom(512)
                elapsed = (time.perf_counter() - start) * 1000.0
            except socket.timeout:
                return None, None, False

            icmp_type, icmp_code = self._parse_icmp(packet)
            responder_ip = addr[0] if addr else None
            reached = bool(
                responder_ip == destination_ip and icmp_type == 3 and icmp_code == 3
            )
            return elapsed, responder_ip, reached
        except OSError as exc:
            if exc.errno in (errno.EPERM, errno.EACCES):
                raise PermissionError from exc
            raise
        finally:
            send_sock.close()
            recv_sock.close()

    def _probe_ipv6(
        self, destination_ip: str, ttl: int, port: int
    ) -> tuple[Optional[float], Optional[str], bool]:
        recv_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        send_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        try:
            recv_sock.settimeout(self.timeout_s)
            recv_sock.bind(("::", port))
            send_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)

            start = time.perf_counter()
            send_sock.sendto(b"", (destination_ip, port, 0, 0))

            try:
                packet, addr = recv_sock.recvfrom(512)
                elapsed = (time.perf_counter() - start) * 1000.0
            except socket.timeout:
                return None, None, False

            icmp_type, icmp_code = self._parse_icmpv6(packet)
            responder_ip = addr[0] if addr else None
            reached = bool(
                responder_ip == destination_ip and icmp_type == 1 and icmp_code == 4
            )
            return elapsed, responder_ip, reached
        except OSError as exc:
            if exc.errno in (errno.EPERM, errno.EACCES):
                raise PermissionError from exc
            raise
        finally:
            send_sock.close()
            recv_sock.close()

    @staticmethod
    def _parse_icmp(packet: bytes) -> tuple[Optional[int], Optional[int]]:
        if len(packet) < 28:
            return None, None
        ip_header_len = (packet[0] & 0x0F) * 4
        if len(packet) < ip_header_len + 2:
            return None, None
        return packet[ip_header_len], packet[ip_header_len + 1]

    @staticmethod
    def _parse_icmpv6(packet: bytes) -> tuple[Optional[int], Optional[int]]:
        if len(packet) < 2:
            return None, None
        return packet[0], packet[1]

    def _geolocate(self, ip: str) -> Optional[dict]:
        # Servicio sin API key para demo; puede tener límites de uso.
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,city,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting"
        )
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                return None
            data = resp.json()
            if data.get("status") != "success":
                return None
            return data
        except requests.RequestException:
            return None

    @staticmethod
    def _network_type_from_flags(mobile: bool, proxy: bool, hosting: bool) -> str:
        kinds = []
        if mobile:
            kinds.append("mobile")
        if hosting:
            kinds.append("hosting")
        if proxy:
            kinds.append("proxy/vpn")
        return ", ".join(kinds) if kinds else "residential/unknown"


class HopsWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Detalle de nodos y latencias")
        self.resize(780, 460)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            [
                "Salto",
                "IP",
                "RTT avg (ms)",
                "RTTs (ms)",
                "Ciudad",
                "País",
                "Owner",
                "ASN",
                "Coordenadas",
            ]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)

    def clear_rows(self) -> None:
        self.table.setRowCount(0)

    def add_hop(self, hop: HopInfo) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        coords = ""
        if hop.lat is not None and hop.lon is not None:
            coords = f"{hop.lat:.4f}, {hop.lon:.4f}"

        values = [
            str(hop.hop),
            hop.ip,
            f"{hop.avg_rtt:.2f}" if hop.avg_rtt is not None else "N/A",
            ", ".join(f"{v:.2f}" for v in hop.rtts_ms) if hop.rtts_ms else "N/A",
            hop.city or "N/A",
            hop.country or "N/A",
            hop.org or hop.isp or "N/A",
            hop.asn or "N/A",
            coords or "N/A",
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, col, item)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Traceroute visual sobre mapa mundial")
        self.resize(1200, 760)

        self.worker: Optional[TracerouteWorker] = None
        self.current_hops: List[HopInfo] = []
        self.trace_history: List[dict] = []
        self.history_file = Path("trace_history.json")
        self.continuous_timer = QTimer(self)
        self.continuous_timer.timeout.connect(self._run_continuous_tick)
        self.continuous_running = False
        self.hops_window = HopsWindow()
        self._load_history_file()

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        top = QHBoxLayout()
        title = QLabel("Destino IP:")
        title.setFont(QFont("Arial", 11))
        top.addWidget(title)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Ejemplo: 8.8.8.8")
        top.addWidget(self.ip_input, stretch=1)

        top.addWidget(QLabel("IP mode:"))
        self.ip_mode_combo = QComboBox()
        self.ip_mode_combo.addItems(["auto", "ipv4", "ipv6"])
        self.ip_mode_combo.setCurrentText("auto")
        top.addWidget(self.ip_mode_combo)

        self.rtt_limit_input = QLineEdit("120")
        self.rtt_limit_input.setMaximumWidth(70)
        self.rtt_limit_input.setToolTip("Umbral RTT medio por salto (ms)")
        top.addWidget(QLabel("RTT>"))
        top.addWidget(self.rtt_limit_input)

        self.jump_limit_input = QLineEdit("40")
        self.jump_limit_input.setMaximumWidth(70)
        self.jump_limit_input.setToolTip("Umbral de incremento brusco entre saltos (ms)")
        top.addWidget(QLabel("Delta>"))
        top.addWidget(self.jump_limit_input)

        self.run_btn = QPushButton("Ejecutar traceroute")
        self.run_btn.clicked.connect(self.start_trace)
        top.addWidget(self.run_btn)

        self.details_btn = QPushButton("Ver detalle de nodos")
        self.details_btn.clicked.connect(self.hops_window.show)
        top.addWidget(self.details_btn)

        self.history_btn = QPushButton("Historial")
        self.history_btn.clicked.connect(self.show_history_summary)
        top.addWidget(self.history_btn)

        self.load_last_btn = QPushButton("Cargar última")
        self.load_last_btn.clicked.connect(self.load_last_trace)
        top.addWidget(self.load_last_btn)

        self.compare_btn = QPushButton("Comparar últimas")
        self.compare_btn.clicked.connect(self.compare_last_two)
        top.addWidget(self.compare_btn)

        self.export_btn = QPushButton("Exportar JSON/CSV")
        self.export_btn.clicked.connect(self.export_current_trace)
        top.addWidget(self.export_btn)

        self.report_btn = QPushButton("Reporte HTML")
        self.report_btn.clicked.connect(self.export_html_report)
        top.addWidget(self.report_btn)

        top.addWidget(QLabel("Cada (min):"))
        self.interval_input = QLineEdit("5")
        self.interval_input.setMaximumWidth(55)
        top.addWidget(self.interval_input)

        self.continuous_btn = QPushButton("Iniciar continuo")
        self.continuous_btn.clicked.connect(self.toggle_continuous_mode)
        top.addWidget(self.continuous_btn)

        layout.addLayout(top)

        self.status = QLabel("Listo")
        layout.addWidget(self.status)

        self.alerts_label = QLabel("Alertas: sin datos")
        self.alerts_label.setStyleSheet("color: #7a5f00;")
        layout.addWidget(self.alerts_label)

        self.web = QWebEngineView()
        layout.addWidget(self.web, stretch=1)

        self._render_map([])

    def start_trace(self) -> None:
        target = self.ip_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Falta destino", "Introduce una IP de destino.")
            return

        self.run_btn.setEnabled(False)
        self.status.setText(f"Ejecutando traceroute a {target}...")
        self.current_hops = []
        self.hops_window.clear_rows()
        self._render_map([])

        self.worker = TracerouteWorker(
            target_ip=target,
            ip_mode=self.ip_mode_combo.currentText(),
        )
        self.worker.hop_found.connect(self.on_hop)
        self.worker.finished_ok.connect(self.on_finish)
        self.worker.failed.connect(self.on_fail)
        self.worker.start()

    def on_hop(self, hop: HopInfo) -> None:
        self.current_hops.append(hop)
        self.hops_window.add_hop(hop)
        geolocated = [h for h in self.current_hops if h.lat is not None and h.lon is not None]
        self._render_map(geolocated)
        self.status.setText(
            f"Trazando... {len(self.current_hops)} saltos detectados, {len(geolocated)} geolocalizados."
        )

    def on_finish(self, hops: List[HopInfo]) -> None:
        self.run_btn.setEnabled(True)
        self.current_hops = list(hops)
        geolocated = [h for h in hops if h.lat is not None and h.lon is not None]
        self._render_map(geolocated)
        self._save_trace_to_history(hops)
        self._evaluate_quality_alerts(hops)
        self.status.setText(
            f"Completado: {len(hops)} saltos detectados, {len(geolocated)} geolocalizados."
        )
        if self.continuous_running:
            self.status.setText(
                f"Completado: {len(hops)} saltos. Modo continuo activo."
            )

    def on_fail(self, msg: str) -> None:
        self.run_btn.setEnabled(True)
        self.status.setText("Error")
        QMessageBox.critical(self, "Traceroute falló", msg)

    def _render_map(self, hops: List[HopInfo]) -> None:
        route_points = []
        for hop in hops:
            if hop.lat is None or hop.lon is None:
                continue
            rtt_text = f"{hop.avg_rtt:.2f} ms" if hop.avg_rtt is not None else "N/A"
            host = hop.hostname or "-"
            owner = hop.org or hop.isp or "-"
            isp = hop.isp or "-"
            asn = hop.asn or "-"
            route_points.append(
                {
                    "hop": hop.hop,
                    "lat": hop.lat,
                    "lon": hop.lon,
                    "ip": hop.ip,
                    "host": host,
                    "city": hop.city or "-",
                    "country": hop.country or "-",
                    "owner": owner,
                    "isp": isp,
                    "asn": asn,
                    "asname": hop.asname or "-",
                    "reverse_dns": hop.reverse_dns or "-",
                    "network_type": hop.network_type or "-",
                    "rtt": rtt_text,
                }
            )

        offline_html = self._build_offline_map_html(hops)
        offline_js_string = json.dumps(offline_html)
        points_js = json.dumps(route_points)

        html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <link
    rel="stylesheet"
    href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
    integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="
    crossorigin=""
  />
  <link
    rel="stylesheet"
    href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css"
  />
  <link
    rel="stylesheet"
    href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css"
  />
  <style>
    html, body, #map {{
      margin: 0;
      width: 100%;
      height: 100%;
      font-family: Arial, sans-serif;
    }}
    .legend {{
      position: absolute;
      z-index: 1000;
      top: 10px;
      left: 10px;
      background: rgba(255,255,255,0.92);
      border: 1px solid #9fb6c8;
      border-radius: 6px;
      padding: 6px 8px;
      color: #243748;
      font-size: 13px;
    }}
    .hop-number div {{
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: #16395f;
      color: #fff;
      border: 1px solid #ffffff;
      font-size: 12px;
      font-weight: 700;
      line-height: 20px;
      text-align: center;
      box-shadow: 0 0 2px rgba(0,0,0,0.5);
    }}
    .multi-hop-popup {{
      min-width: 280px;
      max-width: 360px;
      font-size: 13px;
    }}
    .multi-hop-popup select {{
      width: 100%;
      margin: 6px 0 8px 0;
      padding: 4px;
      border: 1px solid #aac1d3;
      border-radius: 4px;
      background: #fff;
    }}
    .multi-hop-details {{
      border-top: 1px solid #d9e4ed;
      padding-top: 6px;
      line-height: 1.35;
    }}
  </style>
</head>
<body>
  <div class="legend">OpenStreetMap | Saltos geolocalizados: {len(route_points)}</div>
  <div id="map"></div>

  <script>
    const POINTS = {points_js};
    const OFFLINE_HTML = {offline_js_string};
    const HOP_GROUPS = {{}};

    function loadOfflineFallback() {{
      document.open();
      document.write(OFFLINE_HTML);
      document.close();
    }}

    function escHtml(value) {{
      return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }}

    function hopDetailsHtml(hop) {{
      return `
        <div class="multi-hop-details">
          <b>Salto ${{escHtml(hop.hop)}}</b><br>
          IP: ${{escHtml(hop.ip)}}<br>
          Host: ${{escHtml(hop.host || "-")}}<br>
          Ubicación: ${{escHtml(hop.city || "-")}}, ${{escHtml(hop.country || "-")}}<br>
          Propietario: ${{escHtml(hop.owner || "-")}}<br>
          ISP: ${{escHtml(hop.isp || "-")}}<br>
          ASN: ${{escHtml(hop.asn || "-")}}<br>
          AS Name: ${{escHtml(hop.asname || "-")}}<br>
          Reverse DNS: ${{escHtml(hop.reverse_dns || "-")}}<br>
          Tipo red: ${{escHtml(hop.network_type || "-")}}<br>
          RTT avg: ${{escHtml(hop.rtt || "N/A")}}
        </div>
      `;
    }}

    function selectGroupedHop(groupId, hopValue) {{
      const container = document.getElementById(`hop-details-${{groupId}}`);
      const hops = HOP_GROUPS[groupId] || [];
      const selected = hops.find(h => String(h.hop) === String(hopValue));
      if (container) {{
        container.innerHTML = selected ? hopDetailsHtml(selected) : "";
      }}
    }}

    function groupKey(point) {{
      const city = (point.city || "-").trim().toLowerCase();
      const country = (point.country || "-").trim().toLowerCase();
      if (city !== "-" || country !== "-") {{
        return `${{city}}|${{country}}`;
      }}
      // Fallback cuando no haya ciudad/país
      return `${{point.lat.toFixed(3)}}|${{point.lon.toFixed(3)}}`;
    }}

    function initMap() {{
      try {{
        if (!window.L) {{
          throw new Error("Leaflet no disponible");
        }}

        const map = L.map("map", {{
          worldCopyJump: true,
          zoomControl: true
        }}).setView([20, 0], 2);

        L.tileLayer("https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png", {{
          maxZoom: 19,
          attribution: "&copy; OpenStreetMap contributors"
        }}).addTo(map);

        const markerLayer = window.L.markerClusterGroup
          ? L.markerClusterGroup({{
              spiderfyOnMaxZoom: true,
              showCoverageOnHover: false,
              maxClusterRadius: 35
            }})
          : L.layerGroup();

        if (POINTS.length > 0) {{
          const latlngs = [];
          const grouped = {{}};
          for (const p of POINTS) {{
            const latlng = [p.lat, p.lon];
            latlngs.push(latlng);
            const key = groupKey(p);
            if (!grouped[key]) {{
              grouped[key] = [];
            }}
            grouped[key].push(p);
          }}

          let groupIndex = 0;
          for (const [_, hops] of Object.entries(grouped)) {{
            hops.sort((a, b) => a.hop - b.hop);
            const anchor = hops[hops.length - 1];
            const latlng = [anchor.lat, anchor.lon];
            const groupId = `g${{groupIndex++}}`;
            HOP_GROUPS[groupId] = hops;

            let popupHtml = "";
            if (hops.length === 1) {{
              popupHtml = `<div class="multi-hop-popup">${{hopDetailsHtml(hops[0])}}</div>`;
            }} else {{
              const options = hops
                .map(h => `<option value="${{h.hop}}">Salto ${{h.hop}} (${{escHtml(h.ip)}})</option>`)
                .join("");
              popupHtml = `
                <div class="multi-hop-popup">
                  <b>Ubicación compartida</b><br>
                  Hay ${{hops.length}} saltos en este nodo.
                  <select onchange="selectGroupedHop('${{groupId}}', this.value)">
                    ${{options}}
                  </select>
                  <div id="hop-details-${{groupId}}"></div>
                </div>
              `;
            }}

            const hopNumbers = hops.map(h => h.hop).join(",");
            const numIcon = L.divIcon({{
              className: "hop-number",
              html: `<div>${{escHtml(hopNumbers)}}</div>`,
              iconSize: [Math.max(20, 10 + hopNumbers.length * 6), 20],
              iconAnchor: [10, 10]
            }});
            L.marker(latlng, {{ icon: numIcon }})
              .bindPopup(popupHtml)
              .on("popupopen", function() {{
                selectGroupedHop(groupId, hops[0].hop);
              }})
              .addTo(markerLayer);
          }}

          markerLayer.addTo(map);

          if (latlngs.length >= 2) {{
            L.polyline(latlngs, {{
              color: "#1e5aa8",
              weight: 3,
              opacity: 0.85
            }}).addTo(map);
          }}

          const bounds = L.latLngBounds(latlngs);
          map.fitBounds(bounds.pad(0.35));
        }}
      }} catch (err) {{
        loadOfflineFallback();
      }}
    }}
  </script>
  <script
    src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
    integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
    crossorigin=""
  ></script>
  <script src="https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js"></script>
  <script>
    if (window.L) {{
      initMap();
    }} else {{
      loadOfflineFallback();
    }}
  </script>
</body>
</html>"""

        self.web.setHtml(html)

    def _build_offline_map_html(self, hops: List[HopInfo]) -> str:
        width = 1400
        height = 720

        def project(lat: float, lon: float) -> tuple[float, float]:
            # Proyección equirectangular simple (100% local y estable sin red)
            x = (lon + 180.0) / 360.0 * width
            y = (90.0 - lat) / 180.0 * height
            return x, y

        def polygon_path(coords: list[tuple[float, float]]) -> str:
            points = [project(lat, lon) for lat, lon in coords]
            if not points:
                return ""
            start = points[0]
            rest = " ".join(f"L {x:.1f} {y:.1f}" for x, y in points[1:])
            return f"M {start[0]:.1f} {start[1]:.1f} {rest} Z"

        continents = [
            # Norteamérica y Centroamérica
            [
                (72, -168), (70, -150), (68, -140), (65, -126), (59, -117), (54, -130),
                (50, -127), (49, -124), (45, -124), (41, -123), (37, -122), (34, -118),
                (31, -114), (28, -112), (25, -110), (24, -106), (22, -102), (19, -98),
                (18, -94), (16, -90), (14, -88), (12, -86), (10, -84), (9, -80),
                (12, -77), (18, -75), (24, -79), (28, -81), (31, -79), (36, -75),
                (41, -66), (45, -63), (50, -60), (54, -63), (58, -68), (62, -74),
                (66, -85), (69, -100), (72, -120),
            ],
            # Sudamérica
            [
                (12, -82), (10, -79), (9, -76), (7, -74), (4, -72), (1, -78),
                (-4, -80), (-9, -79), (-13, -77), (-17, -74), (-23, -71), (-30, -71),
                (-36, -73), (-43, -73), (-52, -69), (-55, -65), (-54, -59), (-51, -55),
                (-47, -51), (-42, -48), (-35, -46), (-27, -48), (-20, -44), (-12, -39),
                (-5, -36), (1, -44), (6, -50), (9, -58), (10, -66), (11, -74),
            ],
            # Europa + Asia
            [
                (71, -10), (70, 5), (69, 18), (67, 30), (66, 42), (64, 55), (63, 70),
                (61, 83), (58, 95), (55, 105), (51, 115), (47, 126), (43, 137), (39, 142),
                (35, 140), (31, 132), (27, 125), (23, 121), (19, 117), (15, 112), (11, 108),
                (7, 104), (6, 98), (8, 92), (12, 86), (17, 82), (21, 78), (24, 73),
                (27, 68), (31, 63), (35, 58), (38, 53), (40, 48), (41, 43), (40, 37),
                (38, 32), (41, 27), (44, 23), (46, 18), (48, 14), (51, 10), (54, 7),
                (56, 2), (58, -4), (61, -8), (65, -7),
            ],
            # África
            [
                (37, -17), (36, -10), (35, -6), (35, 0), (36, 8), (36, 16), (34, 22),
                (32, 28), (31, 32), (29, 34), (25, 35), (21, 36), (16, 39), (11, 43),
                (6, 46), (2, 48), (-2, 49), (-7, 47), (-12, 45), (-17, 42), (-22, 40),
                (-27, 35), (-32, 31), (-34, 26), (-35, 20), (-35, 14), (-34, 9), (-31, 3),
                (-26, -1), (-21, -5), (-16, -8), (-10, -12), (-3, -14), (4, -14), (11, -15),
                (18, -16), (24, -16), (30, -15), (34, -15),
            ],
            # Australia
            [
                (-11, 113), (-14, 121), (-18, 128), (-21, 135), (-25, 142), (-31, 149),
                (-37, 153), (-42, 147), (-43, 140), (-42, 132), (-39, 124), (-35, 118),
                (-30, 114), (-24, 113), (-18, 113),
            ],
            # Groenlandia
            [
                (82, -73), (80, -60), (77, -50), (74, -44), (70, -38), (65, -40),
                (60, -45), (60, -52), (63, -59), (67, -66), (72, -70), (77, -72),
            ],
            # Madagascar
            [(-12, 49), (-15, 50), (-20, 49), (-24, 47), (-25, 45), (-22, 44), (-17, 45), (-13, 47)],
            # Japón
            [(46, 144), (43, 142), (40, 141), (37, 140), (34, 136), (31, 131), (33, 129), (37, 134), (41, 140)],
            # Reino Unido/Irlanda simplificados
            [(59, -8), (57, -6), (54, -5), (51, -4), (50, -6), (52, -8), (55, -9)],
        ]

        graticule = []
        for lon in range(-180, 181, 30):
            x, _ = project(0, lon)
            graticule.append(
                f'<line x1="{x:.1f}" y1="0" x2="{x:.1f}" y2="{height}" class="grid" />'
            )
        for lat in range(-60, 61, 30):
            _, y = project(lat, 0)
            graticule.append(
                f'<line x1="0" y1="{y:.1f}" x2="{width}" y2="{y:.1f}" class="grid" />'
            )

        continent_paths = [
            f'<path d="{polygon_path(poly)}" class="land" />' for poly in continents
        ]

        route_points = []
        for hop in hops:
            if hop.lat is None or hop.lon is None:
                continue
            x, y = project(hop.lat, hop.lon)
            rtt_text = f"{hop.avg_rtt:.2f} ms" if hop.avg_rtt is not None else "N/A"
            host = hop.hostname or "-"
            tip = escape(
                f"Salto {hop.hop} | IP {hop.ip} | Host {host} | {hop.city or '-'}, {hop.country or '-'} | RTT {rtt_text}"
            )
            route_points.append((x, y, tip))

        polyline = ""
        if len(route_points) >= 2:
            points_attr = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in route_points)
            polyline = f'<polyline points="{points_attr}" class="route" />'

        markers = []
        labels = []
        for idx, (x, y, tip) in enumerate(route_points, start=1):
            markers.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5.5" class="hop"><title>{tip}</title></circle>'
            )
            labels.append(
                f'<text x="{x + 8:.1f}" y="{y - 8:.1f}" class="hop-label">{idx}</text>'
            )

        html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <style>
    html, body {{
      margin: 0;
      height: 100%;
      background: #d7ecff;
      font-family: Arial, sans-serif;
    }}
    .wrap {{
      width: 100%;
      height: 100%;
      display: flex;
      align-items: stretch;
      justify-content: stretch;
    }}
    svg {{
      width: 100%;
      height: 100%;
      background: linear-gradient(#d8eeff 0%, #cae6ff 100%);
    }}
    .grid {{
      stroke: #9ec3df;
      stroke-width: 1;
      opacity: 0.55;
    }}
    .land {{
      fill: #ece8d4;
      stroke: #8f8f84;
      stroke-width: 1.2;
    }}
    .route {{
      fill: none;
      stroke: #1e5aa8;
      stroke-width: 3;
      opacity: 0.9;
    }}
    .hop {{
      fill: #d34f2a;
      stroke: #81270f;
      stroke-width: 1;
    }}
    .hop-label {{
      font-size: 12px;
      font-weight: 700;
      fill: #17324d;
      paint-order: stroke;
      stroke: #ffffff;
      stroke-width: 2px;
    }}
    .legend {{
      position: fixed;
      left: 10px;
      top: 10px;
      background: rgba(255, 255, 255, 0.85);
      border: 1px solid #9fb6c8;
      border-radius: 6px;
      padding: 6px 8px;
      color: #243748;
      font-size: 13px;
    }}
  </style>
</head>
<body>
  <div class="legend">Mapa offline (equirectangular) | Saltos geolocalizados: {len(route_points)}</div>
  <div class="wrap">
    <svg viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet">
      {''.join(graticule)}
      {''.join(continent_paths)}
      {polyline}
      {''.join(markers)}
      {''.join(labels)}
    </svg>
  </div>
</body>
</html>"""

        return html

    def _load_history_file(self) -> None:
        if not self.history_file.exists():
            self.trace_history = []
            return
        try:
            data = json.loads(self.history_file.read_text(encoding="utf-8"))
            self.trace_history = data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            self.trace_history = []

    def _save_history_file(self) -> None:
        try:
            self.history_file.write_text(
                json.dumps(self.trace_history[-30:], ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass

    @staticmethod
    def _hop_to_dict(hop: HopInfo) -> dict:
        return {
            "hop": hop.hop,
            "ip": hop.ip,
            "rtts_ms": hop.rtts_ms,
            "hostname": hop.hostname,
            "city": hop.city,
            "country": hop.country,
            "isp": hop.isp,
            "org": hop.org,
            "asn": hop.asn,
            "asname": hop.asname,
            "reverse_dns": hop.reverse_dns,
            "mobile": hop.mobile,
            "proxy": hop.proxy,
            "hosting": hop.hosting,
            "network_type": hop.network_type,
            "lat": hop.lat,
            "lon": hop.lon,
        }

    @staticmethod
    def _dict_to_hop(data: dict) -> HopInfo:
        return HopInfo(
            hop=int(data.get("hop", 0)),
            ip=str(data.get("ip", "*")),
            rtts_ms=list(data.get("rtts_ms", [])),
            hostname=str(data.get("hostname", "")),
            city=str(data.get("city", "")),
            country=str(data.get("country", "")),
            isp=str(data.get("isp", "")),
            org=str(data.get("org", "")),
            asn=str(data.get("asn", "")),
            asname=str(data.get("asname", "")),
            reverse_dns=str(data.get("reverse_dns", "")),
            mobile=bool(data.get("mobile", False)),
            proxy=bool(data.get("proxy", False)),
            hosting=bool(data.get("hosting", False)),
            network_type=str(data.get("network_type", "")),
            lat=data.get("lat"),
            lon=data.get("lon"),
        )

    def _save_trace_to_history(self, hops: List[HopInfo]) -> None:
        if not hops:
            return
        target = self.ip_input.text().strip()
        item = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "target": target,
            "hops": [self._hop_to_dict(h) for h in hops],
        }
        self.trace_history.append(item)
        self.trace_history = self.trace_history[-30:]
        self._save_history_file()

    def show_history_summary(self) -> None:
        if not self.trace_history:
            QMessageBox.information(self, "Historial", "No hay trazas guardadas.")
            return
        lines = []
        for idx, item in enumerate(self.trace_history[-10:], start=1):
            lines.append(
                f"{idx}. {item.get('timestamp', '-')} | destino {item.get('target', '-')} | "
                f"{len(item.get('hops', []))} saltos"
            )
        QMessageBox.information(
            self,
            "Historial (últimas 10)",
            "\n".join(lines),
        )

    def load_last_trace(self) -> None:
        if not self.trace_history:
            QMessageBox.information(self, "Historial", "No hay trazas guardadas.")
            return
        last = self.trace_history[-1]
        hops = [self._dict_to_hop(h) for h in last.get("hops", [])]
        self.current_hops = hops
        self.hops_window.clear_rows()
        for hop in hops:
            self.hops_window.add_hop(hop)
        geolocated = [h for h in hops if h.lat is not None and h.lon is not None]
        self._render_map(geolocated)
        self.ip_input.setText(str(last.get("target", "")))
        self.status.setText(
            f"Histórico cargado: {last.get('timestamp', '-')} ({len(hops)} saltos)."
        )

    def compare_last_two(self) -> None:
        if len(self.trace_history) < 2:
            QMessageBox.information(
                self,
                "Comparación",
                "Se necesitan al menos 2 trazas guardadas para comparar.",
            )
            return

        prev = self.trace_history[-2]
        curr = self.trace_history[-1]
        prev_hops = {int(h.get("hop", 0)): h for h in prev.get("hops", [])}
        curr_hops = {int(h.get("hop", 0)): h for h in curr.get("hops", [])}
        all_hops = sorted(set(prev_hops.keys()) | set(curr_hops.keys()))

        changed_ip = 0
        changed_asn = 0
        rtt_worse = 0
        details = []

        for hop_n in all_hops:
            a = prev_hops.get(hop_n, {})
            b = curr_hops.get(hop_n, {})
            ip_a = str(a.get("ip", "-"))
            ip_b = str(b.get("ip", "-"))
            asn_a = str(a.get("asn", "-"))
            asn_b = str(b.get("asn", "-"))

            avg_a = self._avg_from_list(a.get("rtts_ms", []))
            avg_b = self._avg_from_list(b.get("rtts_ms", []))

            changes = []
            if ip_a != ip_b:
                changed_ip += 1
                changes.append(f"IP {ip_a} -> {ip_b}")
            if asn_a != asn_b:
                changed_asn += 1
                changes.append(f"ASN {asn_a} -> {asn_b}")
            if avg_a is not None and avg_b is not None and (avg_b - avg_a) > 10.0:
                rtt_worse += 1
                changes.append(f"RTT {avg_a:.2f} -> {avg_b:.2f} ms")

            if changes:
                details.append(f"Salto {hop_n}: " + "; ".join(changes))

        summary = [
            f"Trazas comparadas:",
            f"- Anterior: {prev.get('timestamp', '-')}, destino {prev.get('target', '-')}",
            f"- Actual: {curr.get('timestamp', '-')}, destino {curr.get('target', '-')}",
            "",
            f"Cambios IP: {changed_ip}",
            f"Cambios ASN: {changed_asn}",
            f"Saltos con RTT empeorado (>10 ms): {rtt_worse}",
        ]
        if details:
            summary.append("")
            summary.append("Detalle:")
            summary.extend(details[:25])

        QMessageBox.information(self, "Comparación de rutas", "\n".join(summary))

    @staticmethod
    def _avg_from_list(values: List[float]) -> Optional[float]:
        if not values:
            return None
        return sum(values) / len(values)

    def _get_threshold(self, text: str, fallback: float) -> float:
        try:
            value = float(text.strip())
            if value <= 0:
                return fallback
            return value
        except (ValueError, AttributeError):
            return fallback

    def _evaluate_quality_alerts(self, hops: List[HopInfo]) -> None:
        if not hops:
            self.alerts_label.setText("Alertas: sin datos")
            return

        rtt_limit = self._get_threshold(self.rtt_limit_input.text(), 120.0)
        jump_limit = self._get_threshold(self.jump_limit_input.text(), 40.0)

        alerts = []
        previous_avg: Optional[float] = None

        for hop in hops:
            avg = hop.avg_rtt
            if avg is None:
                alerts.append(f"Salto {hop.hop}: sin respuesta")
                continue

            if avg > rtt_limit:
                alerts.append(f"Salto {hop.hop}: RTT alto ({avg:.2f} ms)")

            if previous_avg is not None and (avg - previous_avg) > jump_limit:
                alerts.append(
                    f"Salto {hop.hop}: aumento brusco ({previous_avg:.2f} -> {avg:.2f} ms)"
                )

            # Pérdida estimada por menos de 3 respuestas
            if len(hop.rtts_ms) < 3:
                loss_pct = 100.0 * (3 - len(hop.rtts_ms)) / 3.0
                alerts.append(f"Salto {hop.hop}: pérdida estimada {loss_pct:.0f}%")

            previous_avg = avg

        if alerts:
            self.alerts_label.setText(f"Alertas: {len(alerts)}")
            self.alerts_label.setStyleSheet("color: #a32020; font-weight: 600;")
            QMessageBox.warning(
                self,
                "Alertas de calidad de ruta",
                "\n".join(alerts[:20]),
            )
        else:
            self.alerts_label.setText("Alertas: sin incidencias")
            self.alerts_label.setStyleSheet("color: #1d6b33; font-weight: 600;")

    def export_current_trace(self) -> None:
        if not self.current_hops:
            QMessageBox.information(self, "Exportación", "No hay traza actual para exportar.")
            return

        out_dir = Path("exports")
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = out_dir / f"trace_{stamp}.json"
        csv_path = out_dir / f"trace_{stamp}.csv"

        target = self.ip_input.text().strip()
        payload = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "target": target,
            "hops": [self._hop_to_dict(h) for h in self.current_hops],
        }
        json_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                [
                    "hop",
                    "ip",
                    "hostname",
                    "avg_rtt_ms",
                    "rtts_ms",
                    "city",
                    "country",
                    "owner",
                    "isp",
                    "asn",
                    "asname",
                    "reverse_dns",
                    "network_type",
                    "lat",
                    "lon",
                ]
            )
            for hop in self.current_hops:
                writer.writerow(
                    [
                        hop.hop,
                        hop.ip,
                        hop.hostname,
                        f"{hop.avg_rtt:.2f}" if hop.avg_rtt is not None else "",
                        ",".join(f"{v:.2f}" for v in hop.rtts_ms),
                        hop.city,
                        hop.country,
                        hop.org or hop.isp,
                        hop.isp,
                        hop.asn,
                        hop.asname,
                        hop.reverse_dns,
                        hop.network_type,
                        hop.lat if hop.lat is not None else "",
                        hop.lon if hop.lon is not None else "",
                    ]
                )

        QMessageBox.information(
            self,
            "Exportación completada",
            f"Archivos generados:\n- {json_path}\n- {csv_path}",
        )

    def export_html_report(self) -> None:
        if not self.current_hops:
            QMessageBox.information(self, "Reporte", "No hay traza actual para reportar.")
            return

        out_dir = Path("exports")
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = out_dir / f"trace_report_{stamp}.html"

        target = escape(self.ip_input.text().strip() or "-")
        total = len(self.current_hops)
        geolocated = len([h for h in self.current_hops if h.lat is not None and h.lon is not None])
        avg_values = [h.avg_rtt for h in self.current_hops if h.avg_rtt is not None]
        overall = f"{(sum(avg_values) / len(avg_values)):.2f} ms" if avg_values else "N/A"

        rows = []
        for h in self.current_hops:
            rows.append(
                "<tr>"
                f"<td>{h.hop}</td>"
                f"<td>{escape(h.ip)}</td>"
                f"<td>{escape(h.hostname or '-')}</td>"
                f"<td>{escape(h.city or '-')}</td>"
                f"<td>{escape(h.country or '-')}</td>"
                f"<td>{escape(h.org or h.isp or '-')}</td>"
                f"<td>{escape(h.asn or '-')}</td>"
                f"<td>{escape(h.asname or '-')}</td>"
                f"<td>{escape(h.network_type or '-')}</td>"
                f"<td>{(f'{h.avg_rtt:.2f} ms' if h.avg_rtt is not None else 'N/A')}</td>"
                "</tr>"
            )

        html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Reporte de traza</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1d2b38; }}
    h1 {{ margin: 0 0 10px 0; }}
    .meta {{ background: #f2f7fb; border: 1px solid #c6d9ea; border-radius: 8px; padding: 10px 12px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 14px; }}
    th, td {{ border: 1px solid #d5e0ea; padding: 7px; text-align: left; font-size: 13px; }}
    th {{ background: #edf4fb; }}
    tr:nth-child(even) {{ background: #fafcff; }}
  </style>
</head>
<body>
  <h1>Reporte de Trazado de Red</h1>
  <div class="meta">
    <div><b>Fecha:</b> {escape(datetime.now().isoformat(timespec="seconds"))}</div>
    <div><b>Destino:</b> {target}</div>
    <div><b>Saltos:</b> {total} | <b>Geolocalizados:</b> {geolocated} | <b>RTT medio global:</b> {overall}</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Salto</th><th>IP</th><th>Host</th><th>Ciudad</th><th>País</th><th>Owner</th><th>ASN</th><th>AS Name</th><th>Tipo red</th><th>RTT avg</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""
        report_path.write_text(html, encoding="utf-8")

        QMessageBox.information(
            self,
            "Reporte generado",
            f"Reporte HTML generado:\n- {report_path}",
        )

    def toggle_continuous_mode(self) -> None:
        if self.continuous_running:
            self.continuous_running = False
            self.continuous_timer.stop()
            self.continuous_btn.setText("Iniciar continuo")
            self.status.setText("Modo continuo detenido.")
            return

        interval_min = self._get_threshold(self.interval_input.text(), 5.0)
        interval_ms = int(interval_min * 60_000)
        self.continuous_running = True
        self.continuous_timer.start(interval_ms)
        self.continuous_btn.setText("Detener continuo")
        self.status.setText(
            f"Modo continuo activo (cada {interval_min:.2f} min). Ejecutando ahora..."
        )
        self._run_continuous_tick()

    def _run_continuous_tick(self) -> None:
        if not self.continuous_running:
            return
        if self.worker and self.worker.isRunning():
            return
        if not self.ip_input.text().strip():
            self.status.setText("Modo continuo pausado: falta destino IP.")
            return
        self.start_trace()


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
