# App de escritorio: traceroute sobre mapa mundial

Esta aplicación en Python permite:
- Introducir una IP de destino.
- Ejecutar traceroute interno (implementado en Python, sin depender de `traceroute`/`tracert` del sistema).
- Mostrar los saltos geolocalizados en un mapa del mundo.
- Abrir una ventana adicional con detalle de nodos y tiempos de respuesta.
- Guardar historial local de trazas, cargar la última y comparar las dos más recientes.
- Exportar la traza actual a JSON/CSV y generar reporte HTML.
- Definir umbrales de calidad (RTT y delta entre saltos) y mostrar alertas automáticas.
- Seleccionar modo de resolución/traza de IP: `auto`, `ipv4` o `ipv6`.
- Activar modo continuo para ejecutar trazas periódicas cada X minutos.
- Agrupar nodos en mapa con clustering y spiderfy al acercar/expandir.
- Enriquecer nodos con AS Name, reverse DNS y tipo de red (mobile/hosting/proxy).
- Elegir proveedor de geolocalización (`ip-api` o `ipwhois`) con caché local en `geo_cache.json`.
- Usar tabla avanzada con búsqueda, filtro por ciudad y resaltado de diferencias frente a la traza anterior.
- Empaquetar ejecutables desktop con PyInstaller para macOS/Linux/Windows.

## Requisitos
- Python 3.10+
- Permisos de administrador/root para abrir sockets ICMP raw (necesarios para traceroute).

## Instalación
```bash
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

## Ejecución
```bash
python app.py
```

## Empaquetado (PyInstaller)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
./packaging/build_mac_linux.sh
```

Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
.\packaging\build_windows.ps1
```

El binario resultante queda en `dist/visualRoutePython/`.

## Notas
- La geolocalización usa `ip-api.com` (sin API key), apto para prototipos.
- El mapa principal usa OpenStreetMap (Leaflet + tiles OSM).
- Si Leaflet/CDN o red fallan, la app activa automáticamente un mapa offline de respaldo.
- Algunos routers bloquean ICMP o no exponen IP pública; esos saltos pueden no geolocalizarse.
