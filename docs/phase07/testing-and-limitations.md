# Pruebas, validación y limitaciones

CI ejecuta Ruff, Black, mypy Linux/Windows, core desktop, contracts, parsers,
simulación Capture Node/tcpreplay, state machines de cgroup v2 y filesystem
seguro, validación estática systemd, dos builds DEB byte-identical y policy
tests. El inventario `iw` usa un pool fijo de hasta ocho workers; la prueba con
4096 VIFs crea ocho tasks, conserva el orden, limita la actividad concurrente a
ocho y drena workers en deadline/cancelación/error. Los tests portables simulan
D-Bus, cgroupfs y dumpcap, pero atraviesan providers, autorización, lifecycle,
cuarentena lógica, staging, manifest y SQLite productivos. No requieren root del
host, nunca cambian interfaces, inician monitor mode o ejecutan tcpreplay.

La matriz portable cubre fingerprint y conflictos de retry, preservación de
metadata original, marker durable antes de `O_EXCL`, crash/restart en cada
autoridad, dos procesos, modificación con igual tamaño, truncate/replacement/
hardlink, artifact root sibling y filesystem separado, `EXDEV`, doctor repetido
byte/inode/mode/mtime-invariante, SQLite ausente/v1/v2 sin sidecars nuevos,
gramática completa de journals e `iw link` vacío sin inferir disconnected.

La matriz de rollback separa tipo observado, tipo canónico y token de comando.
Para el target Ubuntu 24.04 con `iw` 6.7 verifica `AP` canónico → `__ap`, impide
emitir literalmente `AP`, acepta el journal canónico y rechaza AP-VLAN, P2P,
WDS, OCB, NAN y tipos desconocidos antes de workspace, journal o mutación.
También cubre múltiples conexiones NetworkManager: UUID primario explícito,
orden secundario determinista, asociación a interfaz, intent/confirmación
durables por UUID, primaria final, crash/restart sin repetir confirmados y
verificación separada de conjunto, primaria e interfaz. Observaciones
`partial`/`unavailable`, UUID ausente o perfil eliminado conservan recovery.

El retry exacto reiniciado se prueba desde `LinuxPlatformAdapter`: valida
autorización estática, fingerprint, lock, binding e identidad/hash del artifact
antes de inicializar backend, workspace, journal, probes `iw`/dumpcap,
NetworkManager o reconciliadores. Un binding válido retorna metadata original
con `reused=true` aunque el journal vivo sea inseguro; binding corrupto,
incompatible o artifact podado/cambiado falla cerrado sin recaptura ni mutación
del filesystem.

En CI Linux, el fake dumpcap ejecutable atraviesa `CaptureCoordinator`, backend,
`LinuxProcessRunner` y spawn guard. Emite PCAP binario por stdout al descriptor
reservado y diagnostics separados por stderr; las variantes cubren exit no
cero, límite de tamaño, cancelación, timeout y escalamiento por cgroup simulado.
En hosts Windows esta prueba POSIX se marca skipped: no se reporta como validación
local del wiring pidfd/spawn guard.

Pruebas privilegiadas reales están separadas:

```sh
sudo WTO_RUN_PRIVILEGED_LINUX_TESTS=1 \
  pytest agents/desktop/tests/linux -m linux -vv
```

Sólo ejecutar en host descartable, red autorizada, NIC dedicada y consola local.
El sentinel incluido obliga el opt-in. La suite también prepara una prueba real
que crea un descendiente con `setsid()`, verifica contención y exige cleanup del
cgroup; queda skipped si el harness no entrega un subtree v2 delegado. La matriz
de hardware real debe registrar kernel, distro, NetworkManager, driver,
firmware, wiphy, dumpcap y resultado de recuperación.

Limitaciones conocidas:

- no existe rol Capture Node en el contrato de enrollment 1.0.0; el rol es
  policy local y se refleja indirectamente en el manifest;
- task delivery, capture task type y upload público de bytes aún no existen;
  artifacts quedan staged en la outbox local/simulada;
- scan activo Linux queda `not_implemented` para no interferir mediciones;
- tcpreplay real está deliberadamente ausente;
- Flent sólo se detecta/declara; su provider de task espera contrato futuro;
- no hay RPM;
- la master key de `encrypted_file` no rota en Fase 07; cualquier reemplazo
  fuera de un flujo futuro transaccional falla cerrado;
- la cuarentena lógica no libera espacio. La purga física queda para
  mantenimiento offline con el servicio detenido y no existe purger remoto ni
  automático durante startup;
- `systemd-analyze verify` se ejecutó en Ubuntu 24.04 aislado, pero el servicio
  real no fue iniciado; cgroup v2 delegado real, descendientes reales con
  `setsid()`, D-Bus/NetworkManager reales, dumpcap real y sus permissions,
  monitor mode, radiotap, rollback desde tipo AP y restauración de múltiples
  conexiones NetworkManager sobre una NIC real quedan pendientes de un host
  Linux descartable. Los tests simulados no constituyen validación física;
- el opt-in actual de cgroup exige UID efectivo 0 y no valida por sí solo el
  caso productivo `User=wto-capture` + `Delegate=yes` sin `CAP_SYS_ADMIN`; queda
  pendiente un harness CI que ejecute la prueba dentro de esa unidad delegada
  no-root;
- monitor mode anunciado por `iw` no garantiza recepción correcta ni hardware
  validado; una captura no garantiza observar todas las tramas.
