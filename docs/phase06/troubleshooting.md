# Troubleshooting Windows

- `permission_denied` en Native Wi-Fi: habilitar Location para desktop apps según policy; el
  servicio no abre Settings desde Session 0.
- `provider_unavailable` con Win32 1062: WLAN AutoConfig está detenido.
- JSON PowerShell rechazado: ejecutar doctor y revisar policy/module sin copiar datos sensibles.
- Inventario PowerShell agotado: medir por separado CIM/NetTCPIP; ajustar
  `windows_inventory_timeout_seconds` sólo después de corregir el proveedor lento.
  El valor nunca debe dejar el proceso sin límite.
- netsh sin campos: el idioma/formato no fue reconocido; no se reinterpretan posiciones.
- service `DEGRADED`: revisar estado SCM, ImagePath y ACL.
- enrollment pipe timeout: confirmar servicio iniciado y sesión administrativa; el token debe
  ingresarse por prompt oculto o stdin, nunca argumento.
- Npcap AdminOnly: captura seguirá no ejecutable en esta fase.
