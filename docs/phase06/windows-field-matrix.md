# Matriz de campos Windows

| Familia | Fuente primaria | Fallback | Limitación |
|---|---|---|---|
| GUID, nombre, estado, tipo y links | IP Helper `GetIfTable2` | Get-NetAdapter | Driver/OS |
| fabricante y driver | Get-NetAdapter/CIM | ausente explicado | Propiedad no uniforme |
| asociación, SSID, BSSID, calidad, PHY, rates | Native Wi-Fi | netsh sólo si no hubo privacy denial | Location/privacy y driver |
| RSSI directo y frecuencia | Native BSS | RSSI estimado separado | BSS puede estar restringido |
| canal y banda | derivación desde frecuencia válida | ninguno | No inventa frecuencias |
| ancho | no expuesto por el wrapper actual | `null` explicado | No se infiere desde IE |
| IPv4/IPv6, gateway, DNS | NetTCPIP/DnsClient JSON | ausente explicado | Compartments/policy |
| bytes, packets, errors, drops | IP Helper | Get-NetAdapterStatistics | Counter no expuesto queda null |

TX/RX association rate describe el enlace reportado por el driver y nunca se etiqueta como
throughput medido. Todo valor conserva unidad, source, availability, confidence, reason y UTC.
