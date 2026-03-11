$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

python -m pip install -r requirements-dev.txt

pyinstaller `
  --noconfirm `
  --clean `
  --name visualRoutePython `
  --windowed `
  --collect-all PySide6 `
  --hidden-import PySide6.QtWebEngineWidgets `
  app.py

Write-Host "Build completado. Binarios en: $root/dist/visualRoutePython"
