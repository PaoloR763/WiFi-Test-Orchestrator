# Troubleshooting Linux

| Síntoma | Interpretación | Acción |
|---|---|---|
| `networkmanager` provider_unavailable | daemon inactivo/ausente o system bus no accesible | revisar `systemctl status NetworkManager` y D-Bus; ip/iw siguen disponibles |
| `active_connections` partial/unavailable | una conexión desapareció, falló una property o venció el timeout | no inferir desconexión ni mutar la NIC; conservar source errors/provenance y reintentar una lectura completa |
| systemd provider unavailable | `/usr/bin/systemctl` y `/bin/systemctl` faltan o no pasan owner/mode/ancestor validation | corregir la instalación del host; PATH, TOML, env y CLI no son fallback válidos |
| tree containment unavailable | cgroup v2 no está delegado o faltan `cgroup.procs`, `cgroup.events` o `cgroup.kill` | corregir sólo la unidad Capture Node; capture/replay/continuous quedan unavailable y no degradan a PID/PGID |
| `permission_denied` | D-Bus, iw o dumpcap negó acceso | revisar cuenta/unidad/policy; no elevar fuera del runbook |
| `command_missing` | tool opcional no instalada | instalar sólo por gestión del host o aceptar capability unavailable |
| `interface_disconnected` | dato de asociación no existe | no interpretar RSSI/rates como cero |
| `iw link` vacío/truncado/desconocido | output inválido, no evidencia de desconexión | conservar `iw info`, NetworkManager y sysfs; asociación queda unavailable si no existe otra fuente |
| secret store BLOCKED | Secret Service ausente/bloqueado/timeout, o owner/mode/link/cifrado inválido | revisar el backend explícito; no copiar ni rotar `.master-key`; restaurar 0700/0600 desde backup autorizado |
| dumpcap unsafe | setuid o executable group/world-writable | corregir paquete/permisos; no usar chmod 777 |
| monitor provider unavailable | rol/policy/NIC/capabilities incompletos | revisar `iw list`, allowlists y unidad capture |
| capture journal active/manual/ambiguo | rollback no verificado, evidencia insegura o crash | condición BLOCKED; ejecutar runbook de recuperación y no borrar a ciegas |
| `ROLLBACK_VERIFICATION_PENDING` partial/unavailable | conserva prefijo mutante confirmado y última observación; puede faltar el sufijo tras un crash | conservar journal/marker; reanudar sólo pasos no confirmados y, tras confirmarlos todos, reintentar únicamente lecturas |
| snapshot original tipo `AP` | `AP` es la etiqueta canónica; Ubuntu 24.04 `iw` 6.7 exige `__ap` como token de `set type` | usar el mapper cerrado/journal; nunca emitir `AP` ni probar alternativas; AP-VLAN/P2P/WDS/OCB/NAN siguen fail-closed |
| varias conexiones NetworkManager activas | el snapshot completo conserva UUID primario, conjunto, orden y asociación a interfaz | restaurar una secundaria por checkpoint y la primaria al final; verificar conjunto y primaria; no usar display names |
| paso `restore_connection:<uuid>` quedó `planned` | el comando pudo terminar antes del fsync de confirmación | exigir observación completa; confirmar por evidencia si el UUID ya está activo, o continuar sólo si está ausente; con partial/unavailable conservar recovery |
| `connection_profile_missing` | `nmcli` confirmó bajo locale C que el UUID exacto del perfil ya no existe | conservar marker/journal y el UUID original; no sustituir por display name ni alterar la primaria; completar mediante recovery manual autorizado |
| `rollback_mismatch` | la observación fue completa pero difiere del snapshot | conservar evidencia; no retirar recovery ni repetir mutadores sin una decisión segura |
| retry exacto tiene binding durable y `iw`/dumpcap/NM no está disponible | el resultado ya confirmado se resuelve por fingerprint, lock, identidad y hash del artifact antes de dependencias vivas | aceptar sólo `reused=true` con metadata original; no corregir herramientas ni NIC para este retry |
| binding corrupto, incompatible o artifact podado/cambiado | la identidad durable no puede validarse | falla cerrado sin construir captura viva ni recapturar; preservar binding/artifact y resolver manualmente |
| inventario con miles de VIFs `iw` | los detalles se procesan con hasta ocho workers, un `info` y luego un `link` por interfaz | revisar deadline/source errors; timeout, cancelación o desaparición no deben dejar tasks/subprocesses pendientes ni alterar el orden |
| `.pending.<nonce>` íntegro | snapshot durable creado antes de mutar | condición DEGRADED; no promover ni retirar manualmente mientras el servicio pueda reanudar |
| retired/quarantine canónico | journal ya retirado lógicamente | no bloquea doctor; la purga física sigue siendo offline |
| cuarentena o `.pending.<nonce>` inválido | la identidad cambió, el temporal está incompleto o no pudo restaurarse sin overwrite | preservar el objeto, detener mutaciones relacionadas y documentar recuperación manual; no hacer unlink por nombre |
| tcpreplay unavailable | comportamiento esperado sin policy completa | validar namespace, hashes, tool y rol; Fase 07 no ejecuta replay real |
| replay artifact mode/owner/link rechazado | no cumple service-user owner, root 0700, archivo 0400/0600 regular y nlink 1 | corregir provisioning según la política vigente; root/group/0440 no están soportados en esta fase |
| DEB rechaza runtime | falta Python 3.12/venv o falla wheelhouse/pip check | corregir dependencia del host; postinst es offline y no usa Pydantic global |

Comandos read-only útiles:

```sh
sudo sh scripts/linux/doctor.sh endpoint
sudo sh scripts/linux/doctor.sh capture
wto-agent --config /etc/wto-agent/wto-agent.toml inventory
systemctl show wto-agent.service wto-agent-capture.service --no-pager
journalctl -u wto-agent.service -u wto-agent-capture.service --since today
```

En Linux, `doctor` usa una composición estrictamente read-only: no construye el
adapter productivo, stager, SecretStore bootstrap, runtime, coordinator ni
reconciliadores. No crea roots, SQLite, WAL/SHM, locks, backups o cuarentenas;
SQLite se abre `mode=ro`/`query_only` como snapshot inmutable y una carrera se
reporta inconclusa. Un recurso ausente se informa, no se inicializa.

Los logs sólo muestran clases de error y metadata segura; no agregar tokens,
Authorization, SSID sensible o contenido PCAP a tickets sin clasificación y
autorización.
