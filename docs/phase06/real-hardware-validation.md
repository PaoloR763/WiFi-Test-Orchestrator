# Validación Windows real

Estado general: **NOT RUN**.

Checklist pendiente:

- Windows 10 22H2 y Windows 11.
- Windows español e inglés.
- Wi-Fi asociado, múltiples adapters y adapter deshabilitado.
- WlanSvc detenido y permisos/location denegados.
- Scan, RSSI directo/estimado, hidden SSID y 2.4/5/6 GHz.
- Cambio de SSID/BSSID, sleep/resume y reboot.
- Servicio real bajo LocalService, enrollment por pipe y credential rotation.
- Npcap/dumpcap opcional con AdminOnly on/off.
- Install, upgrade, rollback, uninstall y purge.

GitHub Actions no demuestra hardware Wi-Fi, radio, WlanSvc, Npcap, 6 GHz, sleep o reboot.
