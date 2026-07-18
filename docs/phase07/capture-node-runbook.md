# Runbook operativo del Capture Node

## Prerrequisitos

1. Host de laboratorio autorizado con NIC de management separada de la radio
   de captura. Nunca usar automáticamente la interfaz que porta default route.
2. NIC/driver/firmware con monitor mode verificado mediante `iw list`; una
   presencia en documentación no equivale a validación real.
3. dumpcap instalado por administración y `dumpcap -D -M` exitoso bajo la
   cuenta del servicio.
4. cgroup v2 montado y un subtree delegado exclusivamente a
   `wto-agent-capture.service`. Deben estar disponibles `cgroup.procs`,
   `cgroup.events` y `cgroup.kill`; no se requiere `CAP_SYS_ADMIN`.
5. Reloj sincronizado y calidad temporal registrada para correlación.
6. Servidor, canal/frecuencia/ancho, interfaz y límites aprobados.

## Provisionamiento

Mantener inicialmente `capture_enabled = false`. Configurar en
`/etc/wto-agent/capture-node.toml`:

```toml
node_role = "capture_node"
capture_enabled = true
allowed_capture_interfaces = ["wlan1"]
protected_capture_interfaces = ["eth0"]
allowed_capture_channels = [36, 40, 44, 48]
allowed_capture_frequencies_mhz = [5180, 5200, 5220, 5240]
allowed_capture_widths_mhz = [20, 80, 160]
capture_max_duration_seconds = 300
capture_max_size_bytes = 104857600
```

Channel y frecuencia deben formar un par conocido. Width queda en un catálogo
cerrado. La captura usa pcap o pcapng, radiotap, timestamp, wiphy, driver,
interfaz, canal/frecuencia/ancho, provider/method y SHA-256.

Antes del primer efecto, el coordinator autoriza, obtiene un snapshot
completamente restaurable, ejecuta preflight y calcula el fingerprint privado
`capture-functional-v2`. Cubre request, banda, canal primario, frecuencia de
control, ancho, CF1, CF2, versión geométrica, límites solicitado/efectivo,
formato/link type/radiotap/snaplen, políticas snapshot/rollback, provider/method
y argv efectivo de dumpcap. Un binding v1 sólo se reutiliza para 20 MHz; v1 de
80/160 MHz es ambiguo y falla cerrado. La versión de dumpcap queda como
evidencia en el binding, no como semántica garantizada. Mismos IDs con otro
fingerprint son conflicto; un artifact o binding incompleto exige recuperación
manual.

En un retry durable, la validación estática y la autorización mínima del grant
existente preceden al lock de idempotencia y a la lectura del binding. Si
binding y artifact coinciden, devuelve path, manifest, metadata, tamaño, hash y
rollback originales y sólo agrega `reused=true`: no consulta NIC/default route,
NetworkManager, `iw` o dumpcap, no ejecuta preflight y no crea marker, journal ni
reserva. Sólo la ausencia de binding habilita la autorización privilegiada y
los probes de una captura nueva.

Para una captura nueva, tipos P2P/unknown, conexiones sin identidad y radio
incompleta se rechazan antes del marker y del journal.
Una lectura de `active_connections` parcial conserva el subconjunto observado,
queda marcada con provenance/source errors y bloquea toda mutación de la
interfaz. Una desaparición sin datos útiles, un error de property o el timeout
total quedan `unavailable` con valor nulo; tampoco equivalen a una lista vacía.

Antes de reservar el PCAP se crea y fsynca un marker
`RESERVATION_PLANNED`. El nombre autorizado incorpora el operation token del
marker; no se adopta un archivo sólo porque coincida con un nombre de
presentación. Después de `O_EXCL` se valida nombre-descriptor y se registra
`RESERVED` con dev/inode/uid/type/mode/nlink. La secuencia durable continúa por
`CAPTURE_COMPLETE`, `ROLLBACK_VERIFICATION_PENDING`, `INTERFACE_RESTORED`,
`STAGING_INTENT_DURABLE`,
`LOCAL_ARTIFACT_COMMITTED`, `BINDING_PUBLISHED` y `RETIRED`. El marker permanece
activo hasta que el binding inmutable es durable; marker, journal de interfaz,
artifact intent y binding son autoridades separadas y deben coincidir en IDs,
fingerprint y operation token.

El journal de interfaz registra interfaz/tipo, UP/DOWN, managed/unmanaged,
banda, canal primario, frecuencia de control, ancho, CF1/CF2, versión geométrica,
conexión primaria y UUIDs activos, namespace, wiphy y driver. Se hace
fsync del archivo, rename atómico y fsync del directorio antes de mutar la NIC.
Cada intento usa `.<execution-id>.pending.<nonce>`. Sólo un pending íntegro,
creado antes de cualquier mutación, es `DEGRADED` no bloqueante; active válido o
inválido, manual recovery, symlink/hardlink, owner/mode inseguro, nombre ambiguo
o pending corrupto son `BLOCKED`. Retired/quarantine canónico no bloquea y su
historial se inspecciona con límite. La evidencia inválida permanece visible y
no se elimina por nombre.
Luego se desadministra NetworkManager si corresponde, se baja link, cambia
type, sube y ejecuta exactamente `iw dev INTERFACE set freq CONTROL HT20`,
`... CONTROL 80 CF1` o `... CONTROL 160 CF1`. 5 y 6 GHz usan tablas cerradas de
bloques; 5935 MHz/canal 2 sólo admite 20 MHz. 40 y 80+80 MHz siguen rechazados.
Una lectura estructurada debe confirmar control, canal, ancho y centros antes
de dumpcap. Estar en la tabla no reemplaza policy regulatoria, soporte de wiphy
ni soporte del driver.
Cancelación, timeout o falla terminan el líder exclusivamente mediante su pidfd,
usan `cgroup.kill` para descendientes, esperan `populated=0` y siempre ejecutan
rollback. Sin contención cgroup verificada, captura y replay fallan antes del
spawn; no degradan a SID/PGID ni a señales por PID numérico.

Tras el marker durable, el output se reserva antes del spawn con
`O_EXCL|O_NOFOLLOW`, modo `0600` e identidad de inode retenida. `dumpcap` recibe
`-w -`; stdout se conecta al descriptor reservado y stderr queda separado. El
PCAP se fsynca y hashea sobre ese mismo descriptor. Staging crea primero un
intent durable ligado al inode/fingerprint, publica outbox y SQLite, y recién
entonces publica el binding; nunca reabre el source por pathname ni acumula el
PCAP en memoria.

`state_dir` conserva SQLite, markers, bindings y journals. `artifacts_dir`
conserva source PCAP, intents, outbox y bytes finales; puede ser sibling o estar
en otro filesystem. Las transiciones que necesitan rename atómico permanecen
dentro del artifact root y no existe fallback copy+unlink ante `EXDEV`.
El source se crea con nombre ligado a UUID y operation token dentro de ese
root; los bytes finales usan un nombre impredecible sin overwrite ni paths
externos. Tamaño y SHA se verifican antes de crear el Artifact Manifest 1.0.0 y
la entrada de outbox local. El protocolo público aún
no expone upload de bytes; no interpretar staging local/simulado como upload
remoto validado.

## Flent

`traffic.latency_under_load` sólo anuncia `linux-flent` cuando `flent_enabled`,
Flent y netperf están instalados, ambos pasan self-check y existe una allowlist
local de servidores. Su ausencia no degrada el agente. Fase 07 no instala Flent
ni acepta servidores libres desde una task.

## Tcpreplay

La policy requiere rol especializado, binario/self-check, artifact root y hashes
aprobados, interfaz y scenario IDs allowlisted, namespace existente y cotas de
duración/rate/loops/tamaño. La task no contiene destino ni argv libres. Fase 07
ejecuta únicamente validación/simulación y cleanup; no invoca tcpreplay real.
El root aprobado debe ser `0700`; cada artifact, regular, owner del usuario
efectivo del servicio, `st_nlink == 1` y modo `0400` o `0600`. Se abre una vez
con `O_NOFOLLOW` y se hashea desde el descriptor en chunks de hasta 1 MiB.
Root owner, grupo dedicado y `0440` están diferidos y se rechazan en esta fase.

## Cierre

Verificar que rollback sea `complete`, que el cgroup quede vacío/removido, que
no quede journal y que la interfaz recupere tipo, link, radio y estado
NetworkManager. `complete` exige observaciones completas de todas las fuentes;
una lista vacía de UUIDs sólo vale si `nmcli active` terminó correctamente. Si
el estado parece restaurado pero la observación es partial/unavailable, se
conservan journal y marker. Cada mutador que retornó correctamente queda
checkpointed con fsync: tras un crash se ejecuta sólo el sufijo aún no confirmado;
cuando todos están confirmados, los retries posteriores son exclusivamente
read-only. No retirar ni cuarentenar la evidencia manualmente.
Si queda cuarentena o temporal inválido, preservarlo y registrar recuperación
manual. Si la restauración no es completa, no reiniciar capturas:
seguir [recuperación de interfaz](interface-recovery-runbook.md).
