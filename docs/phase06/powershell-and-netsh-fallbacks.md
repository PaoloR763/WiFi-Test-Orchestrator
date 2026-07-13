# PowerShell y netsh

El script empaquetado `network_inventory.ps1` proyecta propiedades primitivas y emite un único
JSON UTF-8 sin BOM. Usa `-NoLogo -NoProfile -NonInteractive`, arrays explícitos y
`ConvertTo-Json -Compress -Depth 8`. Windows PowerShell 5.1 es baseline y PowerShell 7 es matriz
adicional. No se aceptan cmdlets, scripts o parámetros del servidor.

El parser Pydantic es cerrado. Ruido, truncamiento, encoding inválido, exceso de salida o JSON
corrupto rechazan esa fuente.

`netsh wlan show interfaces` es read-only y último fallback. Los parsers en-US, es-AR y es-ES
aceptan UTF-8, Windows-1252/OEM, Unicode, campos ausentes y labels desconocidos. Sus valores usan
confidence menor. Nunca se usa tras un privacy access denied ni para modificar red.
