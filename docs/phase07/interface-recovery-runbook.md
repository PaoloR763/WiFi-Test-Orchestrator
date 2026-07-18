# Runbook de recuperación de interfaz

Un journal presente o `rollback_incomplete` es una condición visible y
bloqueante. No borrar el journal antes de comprobar el estado.

1. Detener nuevas capturas:

   ```sh
   sudo systemctl stop wto-agent-capture.service
   ```

2. Copiar el journal a evidencia protegida y revisar `interface_state`. No
   contiene secretos.
3. Comparar estado actual sin mutar:

   ```sh
   ip -details -statistics -json link show dev wlan1
   iw dev wlan1 info
   nmcli --terse --fields GENERAL.MANAGED,GENERAL.STATE,GENERAL.CONNECTION,GENERAL.CON-UUID device show wlan1
   nmcli --terse --fields UUID,DEVICE connection show --active
   ```

4. En una consola local autorizada, restaurar exactamente el snapshot. Ejemplo
   para tipo managed y link originalmente UP:

   ```sh
   sudo ip link set dev wlan1 down
   sudo iw dev wlan1 set type managed
   sudo ip link set dev wlan1 up
   sudo nmcli device set wlan1 managed yes
   sudo nmcli connection up uuid 'UUID_SECUNDARIA_1' ifname wlan1
   sudo nmcli connection up uuid 'UUID_SECUNDARIA_2' ifname wlan1
   sudo nmcli connection up uuid 'UUID_PRIMARIA' ifname wlan1
   ```

   No copiar estos valores a ciegas: interface, tipo, link, canal, UUIDs y
   conexión salen del journal. Para 80/160 MHz, restaurar con el control y CF1
   persistidos (`set freq CONTROL 80 CF1` o `160 CF1`); no reconstruir un centro
   ausente. Un journal ancho histórico sin centro requiere recuperación manual.

   Si el tipo canónico original es `AP`, la versión objetivo Ubuntu 24.04 usa
   `iw` 6.7 y el token de comando verificado es `__ap`:

   ```sh
   sudo iw dev wlan1 set type __ap
   ```

   `AP` es la etiqueta observada/canónica y no es un argumento válido para esa
   versión de `iw`. No sustituirla por tokens tentativos. `AP-VLAN`, P2P, WDS,
   OCB, NAN y tipos desconocidos siguen sin rollback automático y requieren
   preflight fail-closed o recuperación manual.

   Para NetworkManager, usar exclusivamente los UUIDs y la asociación a
   interfaz registrados. Restaurar las secundarias en el orden durable del
   journal y la primaria en el último comando separado; nunca seleccionar por
   display name. Cada `restore_connection:<uuid>` y
   `restore_primary_connection:<uuid>` tiene checkpoint propio. Un UUID ya
   confirmado no se repite. Si quedó `planned` porque el comando pudo terminar
   antes del checkpoint, observar primero el conjunto activo y la primaria; una
   vista `partial`/`unavailable` no autoriza repetir ni retirar recovery.
5. Repetir consultas y comprobar interfaz, tipo canónico, UP/DOWN, managed,
   conexión primaria, UUIDs activos, radio/centros, namespace, wiphy y driver.
   Todas las consultas deben haber terminado de forma completa: `()` observado
   no equivale a `()` por timeout/error. Confirmar que la default route de
   management nunca cambió.
6. Archivar evidencia, eliminar únicamente el journal ya resuelto y ejecutar:

   ```sh
   sudo sh scripts/linux/doctor.sh capture
   ```

7. Iniciar el servicio sólo después de doctor sin BLOCKED.

`ROLLBACK_VERIFICATION_PENDING` conserva tanto el prefijo de mutadores confirmado
durablemente como la última evaluación. Tras un crash, el agente ejecuta sólo el
sufijo todavía no confirmado; una vez confirmado el conjunto completo, cada retry
es read-only y vuelve a observar las fuentes autoritativas. No repetir comandos
confirmados ni borrar evidencia. La retirada requiere que
`verify_active_connections`, `verify_primary_connection` y
`verify_interface_state` confirmen una observación completa. Un
`rollback_mismatch` también conserva evidencia y requiere evaluación segura. Un
journal histórico sin UUID primario demostrable no permite inventarlo: queda en
recuperación manual.

Si driver/firmware no permite volver a managed, mantener el servicio detenido,
preservar PCAP/journal/logs y escalar al administrador del laboratorio. No
reiniciar el host automáticamente ni descargar/reinstalar drivers desde el
agente.
