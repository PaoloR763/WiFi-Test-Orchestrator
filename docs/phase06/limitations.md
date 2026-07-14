# Limitaciones de Fase 06

- Sin endpoints nuevos ni consumo de stubs internos.
- Sin publicación de inventario/telemetría al servidor.
- Sin ICMP/TCP/HTTP probes.
- Sin iperf3 ni detección de iperf3.
- Sin traffic engine ni reservas.
- Sin captura IP real ni monitor mode.
- Sin task remota de connect/disconnect/scan.
- Sin MSI/MSIX/WiX, firma real o auto-update.
- PowerShell/netsh pueden estar restringidos por policy o localización no conocida.
- Channel width permanece unavailable en el provider actual; RSSI directo, 6 GHz y PHY dependen
  de OS, hardware, driver y permisos.
- Validación de hardware real permanece NOT RUN.
