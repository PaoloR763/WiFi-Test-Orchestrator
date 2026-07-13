# PowerShell y netsh

El script empaquetado `network_inventory.ps1` proyecta propiedades primitivas y emite un único
JSON UTF-8 sin BOM. Usa `-NoLogo -NoProfile -NonInteractive`, arrays explícitos y
`ConvertTo-Json -Compress -Depth 8`. Windows PowerShell 5.1 es baseline y PowerShell 7 es matriz
adicional. No se aceptan cmdlets, scripts o parámetros del servidor.

Las siete fuentes (`Get-NetAdapter`, estadísticas, configuración IP, direcciones,
rutas, DNS y drivers firmados) se consultan globalmente una vez y se indexan por
interface index o device ID antes de ensamblar adaptadores. La consulta de
`Win32_PnPSignedDriver` proyecta sólo cinco propiedades, tiene un timeout CIM de
8 segundos y es opcional: si falla, los campos de driver quedan nulos sin bloquear
el resto. El proceso completo conserva un límite finito configurable mediante
`windows_inventory_timeout_seconds` (30 segundos por defecto).

Si una fuente global de estadísticas, configuración IP, direcciones, rutas o DNS
falla, el JSON se sigue generando y el campo `*_available` correspondiente queda
en `false`; listas vacías y valores nulos no se reinterpretan como mediciones.

El parser Pydantic es cerrado. Ruido, truncamiento, encoding inválido, exceso de salida o JSON
corrupto rechazan esa fuente.

`netsh wlan show interfaces` es read-only y último fallback. Los parsers en-US, es-AR y es-ES
aceptan UTF-8, Windows-1252/OEM, Unicode, campos ausentes y labels desconocidos. Sus valores usan
confidence menor. Nunca se usa tras un privacy access denied ni para modificar red.
