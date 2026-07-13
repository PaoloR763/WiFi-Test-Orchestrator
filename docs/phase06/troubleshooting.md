# Troubleshooting Windows

- `permission_denied` en Native Wi-Fi: habilitar Location para desktop apps según policy; el
  servicio no abre Settings desde Session 0.
- `provider_unavailable` con Win32 1062: WLAN AutoConfig está detenido.
- JSON PowerShell rechazado: ejecutar doctor y revisar policy/module sin copiar datos sensibles.
- Inventario PowerShell lento o agotado: ejecutar un diagnóstico controlado con
  `WTO_INVENTORY_DIAGNOSTICS=1` y capturar stderr separado de stdout. Las líneas
  `wto_inventory provider=...` identifican si drivers, adaptadores, estadísticas,
  configuración IP, direcciones, rutas o DNS excedieron su presupuesto; stdout
  debe seguir conteniendo un único JSON parseable.
- Un proveedor con `status=timed_out` se descarta de forma fail-soft: su
  colección queda vacía, los derivados quedan nulos y los flags
  `*_available` aplicables quedan en `false`. Corregir el proveedor o subsistema
  Windows responsable; no aumentar el timeout externo productivo por encima de
  30 segundos.
- En un timeout normal, la misma línea diagnóstica debe mostrar
  `termination=process_handle`: el coordinador retuvo el handle del proceso
  concreto, validó PID, creation time e imagen por ese mismo handle, ejecutó
  `TerminateProcess` sin reabrir el PID y cerró el Job Object individual para
  incluir descendientes. `handle_termination_failed` requiere investigación y
  nunca habilita un fallback que vuelva a resolver el PID.
- Un timeout con `termination=launch_handle` durante el startup de 5 segundos
  significa que el worker explícito no publicó su marker: su `StartEvent` no fue
  liberado y el provider nunca entró. Los providers que sí publicaron marker
  comparten un único timestamp de inicio al liberarse juntos sus gates.
- Verificar la línea
  `wto_inventory cleanup jobs_remaining=0 processes_remaining=0`. Un valor
  distinto de cero indica una falla del cleanup y no debe ignorarse.
  `jobs_remaining` es un campo de compatibilidad y debe ser cero porque esta
  arquitectura no crea jobs PowerShell; `processes_remaining` también cuenta
  streams o lifecycle cuya disposición no pudo verificarse.
- El watchdog usa 8/8/5/10/5/5/5 segundos desde un release común, 3 segundos
  compartidos de reap y 1 segundo final para cerrar Job Objects y esperar
  handles estables. Startup tiene 5 segundos, la fase de providers 20 y el
  coordinador 26, incluida una reserva final de ensamblado de 1 segundo y otro
  segundo de margen antes del watchdog externo. Si el tiempo restante o el
  timeout externo comunicado internamente por
  `WTO_INVENTORY_OUTER_TIMEOUT_MILLISECONDS` no permiten cumplirlos completos,
  todos los gates permanecen cerrados y el resultado es fail-soft; no se
  recortan budgets individuales.
- El timeout externo de 30 segundos es sólo la última barrera. Si se alcanza,
  el process runner ya había creado el coordinador suspendido y lo había
  asignado al Job Object externo antes de `ResumeThread`. El deadline de la
  solicitud comenzó antes del spawn; el cleanup adicional está acotado a 5
  segundos y reserva sus últimos 100 ms para cerrar Job, pipes, transport y
  handles y drenar tareas controladas.
- netsh sin campos: el idioma/formato no fue reconocido; no se reinterpretan posiciones.
- service `DEGRADED`: revisar estado SCM, ImagePath y ACL.
- enrollment pipe timeout: confirmar servicio iniciado y sesión administrativa; el token debe
  ingresarse por prompt oculto o stdin, nunca argumento.
- Npcap AdminOnly: captura seguirá no ejecutable en esta fase.
