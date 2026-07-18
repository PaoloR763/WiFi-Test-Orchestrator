# Seguridad, systemd y permisos

## Hardening

Ambas unidades usan cuenta dedicada, UMask 0077, NoNewPrivileges, PrivateTmp,
PrivateDevices, ProtectSystem strict, ProtectHome, protecciones de kernel,
logs/clock/hostname, RestrictNamespaces, RestrictSUIDSGID, LockPersonality,
MemoryDenyWriteExecute, address families explícitas y paths de escritura
acotados.

El endpoint tiene CapabilityBoundingSet y AmbientCapabilities vacíos y no
admite AF_PACKET. El Capture Node limita ambos sets a CAP_NET_ADMIN y
CAP_NET_RAW, agrega AF_PACKET y nunca recibe CAP_SYS_ADMIN. Tcpreplay real no se
implementa porque entrar arbitrariamente a namespaces requeriría ampliar el
modelo de privilegios; Fase 07 sólo valida/simula.

La unidad endpoint conserva `ProtectControlGroups=yes` y no recibe delegación.
Sólo `wto-agent-capture.service` usa `Delegate=yes`, `KillMode=control-group` y
`ProtectControlGroups=no`: la escritura queda limitada al subtree que systemd
delega a esa cuenta, sin conceder `CAP_SYS_ADMIN`. Si el cgroup v2 delegado no
expone `cgroup.procs`, `cgroup.events` y `cgroup.kill` de forma segura, captura,
replay, Flent y cualquier ejecución que prometa cleanup de árbol fallan antes
del spawn. Readiness crea un leaf local transitorio, valida allí owner, modos y
acceso real a los controles (incluido `cgroup.kill`), lo confirma vacío y lo
elimina por identidad; no exige escritura de `cgroup.kill` en el parent que
systemd conserva bajo su control.

## Secretos

Secret Service se usa sólo si la colección ya está desbloqueada; el agente nunca
abre un prompt. El default y las configuraciones heredadas de Fase 05 fallan
cerrado en Secret Service. `auto` conserva esa semántica y no concede fallback
persistente. `encrypted_file` requiere opt-in explícito; los ejemplos DEB lo
declaran porque sus cuentas de servicio son headless.

Inicialización, búsqueda, creación, lectura y borrado de Secret Service se
ejecutan fuera del event loop con presupuesto total y límite por operación. Un
timeout, cancelación, colección bloqueada o D-Bus no disponible deja el backend
fail-closed y no cambia a archivos.

`encrypted_file` usa AES-GCM, master key 0600 y directorios 0700. Las operaciones
se anclan al descriptor del directorio privado, abren con `O_NOFOLLOW`, exigen
owner efectivo, archivo regular y `st_nlink == 1`, escriben temporales privados
y conservan abierto su descriptor hasta validar el nombre final. La creación
publica con `renameat2(RENAME_NOREPLACE)`; un update exige
`renameat2(RENAME_EXCHANGE)` y falla cerrado si no está disponible. Antes de
confirmar, el final debe coincidir exactamente con el inode temporal, contener
el ciphertext esperado y autenticar mediante AES-GCM al plaintext solicitado.
Corrupción, tag inválido, hardlinks, symlinks, owner o modes incorrectos fallan
cerrado.

Retiros de secretos, master keys propias, temporales, intents, artifacts y
journals usan una única primitiva descriptor-relative de cuarentena lógica:
mueven el nombre activo a una cuarentena impredecible con
`renameat2(RENAME_NOREPLACE)`, reabren con `O_NOFOLLOW`, comparan
device/inode/owner/tipo/mode/link count y hacen fsync del directorio. La ruta
online no ejecuta borrado físico por nombre. Un mismatch no elimina ningún
objeto: intenta restaurarlo sin overwrite y deja estado visible para
recuperación manual si no puede hacerlo.

La eliminación física requiere mantenimiento offline con el servicio detenido
y revisión de los objetos retenidos. Un proceso hostil con el mismo UID está
fuera de esta frontera: Linux no ofrece un unlink de archivo regular por
descriptor que cierre la carrera sobre el nombre de cuarentena. Por eso la
cuarentena puede consumir espacio hasta ser inspeccionada y ningún caller
declara bytes liberados mientras sólo exista el retiro lógico.

La recuperación de journals vuelve a leer desde el descriptor publicado y
compara inode, tamaño, mtime y contenido exacto antes de aceptar el rename. Un
reemplazo o escritura in-place se mueve sin overwrite a un nombre de recovery y
nunca se promueve como snapshot restaurable.

La frontera primaria es owner + 0700/0600. AES-GCM aporta integridad y reduce
exposición parcial del contenido, pero otro proceso con el mismo UID tiene una
frontera limitada. La cuarentena separa el nombre activo sin afirmar purga
race-free frente a ese actor y no convierte un directorio compartido en una
frontera de seguridad completa. Fase 07 no implementa rotación de la master key: no se debe
reemplazar manualmente y una sustitución se rechaza; la rotación queda pendiente
de un flujo futuro transaccional. SQLite, argumentos, diagnostics, journald y
artifacts no contienen tokens ni key material.

## dumpcap

El detector diferencia ausencia, file capabilities ausentes o excesivas,
self-check fallido, acceso permitido, denegación y executable inseguro (setuid
o group/world-writable). Sólo acepta `cap_net_admin`/`cap_net_raw` cuando existen.
El paquete no
instala ni cambia dumpcap/Wireshark/tcpdump/aircrack-ng, drivers o firmware.

En un laboratorio autorizado, la administración puede usar el mecanismo de su
distribución. Si decide file capabilities, el máximo recomendado para dumpcap
es:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
getcap /usr/bin/dumpcap
dumpcap -D -M
```

Esto amplía la capacidad de captura de todo usuario que pueda ejecutar el
binario; restringir grupo/ACL, registrar el cambio y volver a evaluar después
de cada upgrade. No usar chmod 777 ni setuid. El agente no ejecuta `setcap`.

El output se reserva antes del spawn con `O_CREAT|O_EXCL|O_NOFOLLOW`, modo 0600
y descriptor retenido. `dumpcap` recibe `-w -` y stdout se conecta directamente
a ese descriptor; stderr permanece separado y no existe buffer PCAP ilimitado
en memoria. Staging copia y calcula SHA-256 desde el mismo descriptor, no vuelve
a abrir el source por un pathname mutable.

La contención cgroup protege el árbol de procesos de providers confiables aunque
un descendiente use `fork()` o `setsid()`. No es una frontera frente a código
hostil que ya ejecute como el mismo `User=wto-capture`: esa cuenta debe ser
exclusiva y el subtree delegado no debe compartirse con otros servicios. La
misma limitación de actor con igual UID aplica a los directorios privados.

## Threat model específico

| Amenaza | Control |
|---|---|
| Capturar la NIC de management | selección explícita, protected list y rechazo de default route IPv4/IPv6 |
| Quedar en monitor mode | snapshot durable previo, finally rollback y doctor BLOCKED si queda journal |
| PCAP excesivo/sensible | duración, filesize, UMask, path cerrado, hash y clasificación pcap/pcapng |
| Argument injection | Pydantic extra-forbid, regex, argv separado y command IDs locales |
| PID reuse o descendiente con `setsid()` | spawn guard, líder pidfd-only y cgroup v2 privado verificado antes del release; `cgroup.kill` completa el cleanup del árbol |
| Reemplazo durante retiro lógico | identidad dev/inode + cuarentena no-overwrite; no hay unlink online y el mismatch se conserva para recuperación manual |
| Replay fuera del lab | endpoint excluido, scenario/interface/hash/namespace allowlists y simulación sin ejecución |
| Tool de tráfico/captura sustituida | path resuelto, mode seguro, fingerprint antes/después de spawn y self-check |
| `systemctl` sustituido por PATH/config | candidatos cerrados `/usr/bin` y `/bin`, owner root, modo y ancestros confiables; sin fallback por PATH, TOML, env o CLI |
