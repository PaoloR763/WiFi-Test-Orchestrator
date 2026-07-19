# Distribuciones, DEB y lifecycle

## Matriz inicial

| Distribución | Estado | Notas |
|---|---|---|
| Ubuntu 24.04 LTS | objetivo DEB inicial | Python 3.12 de distribución; CI estática/simulada |
| Ubuntu 22.04 LTS | arquitectura soportada condicional | requiere Python 3.12 aprobado antes del DEB; no se descarga durante instalación |
| Debian 12 | condicional | Python 3.11 por defecto no satisface el paquete; provisionar 3.12 de forma administrada |
| Debian 13 | previsto | validar versiones de dependencias y hardware antes de declarar soporte |
| Fedora/RHEL | diseño previsto | systemd y adapters son portables; RPM no está implementado |

Baseline del agente: Python 3.12+. El DEB usa la arquitectura Linux del build
porque contiene wheels binarios. Incluye el wheel del agente, un wheelhouse
Linux fijado y `requirements-linux-runtime.lock`. `postinst` crea
`/usr/lib/wto-agent/venv` e instala exclusivamente con `--no-index`,
`--find-links` y `--no-deps`; no modifica el Python ni el Pydantic del sistema.

Ubuntu 24.04 LTS es el target inicial de publicación segura de artifacts. El
stager requiere `renameat2(RENAME_NOREPLACE)` en kernel y libc para publicar un
objeto sin sobrescritura. Si esa operación no está disponible, el staging falla
cerrado con un error de provider no disponible: no existe fallback mediante
hardlink/unlink ni mediante rename con sobrescritura.

## Layout

| Path | Propósito |
|---|---|
| `/usr/bin/wto-agent` | launcher fijo |
| `/usr/lib/wto-agent/runtime` | wheelhouse y lock inmutables del paquete |
| `/usr/lib/wto-agent/venv` | runtime privado regenerado offline por postinst |
| `/etc/wto-agent/*.toml` | conffiles root-owned |
| `/lib/systemd/system/wto-agent*.service` | unidades endpoint/capture |
| `/var/lib/wto-agent*` | estado: SQLite, secretos, journals, markers y bindings 0700 |
| `artifacts_dir` (default bajo state) | source PCAP, intents, outbox y artifacts finales 0700 |
| `/var/log/wto-agent*` | directorios administrados por systemd |

`artifacts_dir` puede ser un sibling o un volumen/filesystem distinto de
`state_dir`; no necesita ser descendiente ni compartir `st_dev`. Ambos roots se
validan y preparan independientemente. Outbox, intents, temporales y bytes
finales permanecen dentro del artifact root para conservar atomicidad; `EXDEV`
falla cerrado y no habilita copy+unlink.

## Build reproducible

```sh
SOURCE_DATE_EPOCH=0 WTO_AGENT_VERSION=0.1.0 \
  sh scripts/linux/build-deb.sh packages/linux
```

El build consume un wheelhouse Linux preconstruido desde
`WTO_AGENT_WHEELHOUSE` (por defecto `/opt/wto-wheelhouse`). No resuelve ni
descarga dependencias al construir el wheel del agente.

El build normaliza timestamps, usa owner root, compresión uniforme y genera
SHA-256 del DEB y del payload inmutable. CI construye dos veces y compara bytes.

## Instalación no interactiva

```sh
sudo sh scripts/linux/install-agent.sh \
  ./wto-agent_0.1.0_amd64.deb LOWERCASE_SHA256
```

La instalación crea `wto-agent` y `wto-capture`, valida integridad/imports,
hace daemon-reload y habilita sólo la unidad endpoint. No inicia servicios ni
instala herramientas opcionales. Editar config, enrolar y recién entonces usar
`systemctl start wto-agent.service`.

Sólo `wto-agent-capture.service` solicita `Delegate=yes`,
`KillMode=control-group` y acceso de escritura a su subtree cgroup. La unidad
endpoint conserva `ProtectControlGroups=yes`; ninguna agrega `CAP_SYS_ADMIN`.

El `postinst` valida SHA-256 y crea el venv sin red. Luego verifica Pydantic 2,
`AgentSettings`, ambas configuraciones y `pip check`. Cualquier fallo aborta la
instalación o upgrade antes de iniciar servicios.

## Retención de artifacts

El startup reconcilia intents y filas `pending`, `in_flight` o `failed`; los
confirmados no se vuelven a hashear ni consumen el presupuesto de arranque. El
mantenimiento soportado es `wto-agent maintenance prune-artifacts --confirm`,
con límites configurables por edad, cantidad, bytes y lote. Sólo selecciona
filas `confirmed` cuyo archivo regular, owner, link count, path, tamaño y SHA
fueron validados. La identidad del inode se retiene y el nombre se mueve sin
overwrite a una cuarentena impredecible, se reabre con `O_NOFOLLOW`, se compara
y se hace fsync del outbox. La fila se conserva y, sin cambiar schema, su path
se actualiza al nombre de cuarentena para mantener localizable el objeto. El
reporte indica `physical_delete_pending`; no incrementa archivos, filas o bytes
eliminados. Un reemplazo, una fila confirmada sin archivo, pending, symlinks,
hardlinks, orphans e inconsistencias se conservan como estado visible.

La purga física no está automatizada en Fase 07. Requiere mantenimiento offline
con el servicio detenido, inspección previa y una política administrativa
separada; la cuarentena seguirá consumiendo espacio hasta entonces.

## Upgrade, rollback y uninstall

```sh
sudo sh scripts/linux/upgrade-agent.sh NEW.deb SHA256
sudo sh scripts/linux/rollback-agent.sh OLD.deb SHA256 \
  /var/lib/wto-agent/agent.sqlite3.pre-upgrade.bak --confirm-rollback
sudo sh scripts/linux/uninstall-agent.sh
```

Upgrade detiene unidades, crea backup SQLite verificado, instala y sólo reinicia
las unidades que estaban activas. Rollback deja las unidades detenidas para
ejecutar doctor antes de iniciar. Uninstall conserva `/var/lib`; sólo
`uninstall-agent.sh --purge-data` solicita borrado explícito de estado e
identidad.

Si existe estado de Capture Node, upgrade también genera
`/var/lib/wto-agent-capture/agent.sqlite3.pre-upgrade.bak`. Rollback selecciona
automáticamente la configuración endpoint o Capture Node según el directorio
del backup aprobado.

No existe downgrade DDL. Si una versión anterior no entiende el schema SQLite,
restaurar el backup previo; nunca borrar la base para ocultar incompatibilidad.
