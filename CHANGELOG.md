# Changelog

Todos los cambios relevantes de WiFi Test Orchestrator se documentarán en este
archivo.

El formato se inspira en Keep a Changelog y el producto utilizará Semantic
Versioning cuando existan releases publicadas.

## Unreleased

- Corregido el replay exacto de heartbeat y mobile presence: un body durable ya
  aceptado puede recuperar su acknowledgement después de vencer el skew de
  `agent_reported_at`, siempre bajo autenticación, timestamp HTTP, nonce,
  revocación y rate limit vigentes. El replay no extiende presencia ni modifica
  timestamps, `last_seen_at`, manifest, auditoría o versión persistida; no hay
  cambios de schema, OpenAPI o migraciones.
- Agregado C09 del agente Android: modelos JVM puros de conectividad, perfiles
  `BASIC` y `WIFI_TEST_AUTHORIZED`, observación lazy de la red por defecto,
  asociación Wi-Fi separada, SSID/BSSID autorizados y redactados en
  representaciones textuales, RSSI/frecuencia/banda/canal/link rates/
  standard/security sujetos a API y permisos, UTC/monotonic/sequence y
  lifecycle determinista. API 29–30 conserva `WifiManager` como evidencia
  legacy no network-scoped; API 31+ usa `WifiInfo` recibido por callback.
  Declara sólo `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`,
  `ACCESS_COARSE_LOCATION` y `ACCESS_FINE_LOCATION`: COARSE acompaña a FINE
  para un futuro request preciso válido en API 31+, aunque C09 no solicita
  permisos mediante UI y sólo FINE concedido habilita el intento de
  SSID/BSSID. No agrega `NEARBY_WIFI_DEVICES`, componentes, persistencia,
  transporte, scan, control Wi-Fi, probes, tráfico, UI o ejecución background.
- Agregado C08 del agente Android: catálogo determinista de 15 capabilities,
  fingerprint semántico, secuencia inicial 0 y monotónica, snapshot pending
  congelado, Room v3 con migración 2→3/guards/lectura raw fail-closed,
  publicación `PUT` HTTPS autenticada, ack estricto, retry idempotente,
  recuperación ante ambigüedad/process recreation y composición lazy con
  `BuildConfig.VERSION_NAME`. No agrega permisos, componentes, UI, lifecycle,
  tareas, probes, tráfico, captura ni CI.
- Agregado el coordinador de enrolamiento Android C07 en `:core:data`: intento
  efímero congelado, mutex y guard globales de proceso, preflight C06 antes de
  Keystore, `inspect`/`prepare` excluyentes, bridge cancellable para una única
  llamada C03, protección inmediata C05, persistencia C06, reconciliación
  read-only acotada, resultados cerrados/redactados y composición lazy desde
  `:app`. No incorpora retries automáticos, UI, lifecycle, nuevos contratos,
  endpoints, permisos, schemas o migraciones.
- Agregada la persistencia Android C06 con Room v2: tabla singleton
  `protected_enrollment`, migración explícita 1→2 sin backfill, identidad
  backend y metadata `ACTIVE`, envelope AES-GCM C05, reconstrucción
  fail-closed, resultados `Unsupported`/`Corrupt` separados, equivalencia que
  preserva ciphertext, rotación monotónica, bloqueo del cambio de servidor,
  transacciones verificadas y tests de migración, SQL adversarial, seguridad y
  concurrencia. No persiste plaintext o token, no depende de
  `CredentialProtector` y no implementa coordinador ni networking.
- Agregada la base criptográfica Android C05: port JVM puro, envelope/AAD v1
  cerrados, clave AES-256-GCM administrada por Android Keystore, lifecycle
  idempotente, descifrado callback-scoped, redacción, zeroization best-effort y
  tests JVM/Robolectric host. No persiste credentials ni modifica Room; la
  validación estricta acepta en API 29–36.0 la limitación conocida
  `NOT_OBSERVABLE` sólo para el alias v1 y con todos los demás atributos exactos;
  desde API 36.1 exige evidencia observada `NOT_REQUIRED`.
- Agregada la base Android C04 con Room v1 para identidad de instalación,
  configuración HTTPS actual y timestamps nanosegundo únicamente; usa apertura
  lazy bajo no-backup, WAL, errores redactados, corrupción fail-closed, schema
  versionado, políticas de exclusión de backup y tests JVM herméticos con
  Robolectric/SQLite real, sin persistir enrolamiento, credentials o secretos.
- Preservado el default fail-closed de secretos Linux de Fase 05; Secret
  Service completo ahora está acotado fuera del event loop, el store AES-GCM
  opera descriptor-anchored y capabilities/systemd/NetworkManager publican
  readiness actual bajo presupuestos totales por ciclo.
- Agregado el adapter Linux NetworkManager/D-Bus-first con inventario
  normalizado, fallbacks allowlisted `ip` JSON/`iw`/`ethtool`, clasificación de
  fallas y secretos headless AES-GCM con paths 0700/0600.
- Agregado el rol local explícito Capture Node: dumpcap condicionado por
  detección/permisos/policy, selección de radio por frecuencia, radiotap,
  idempotencia previa a la NIC, artifact outbox/retención, snapshot restaurable,
  journal durable y rollback verificado de interfaz.
- Cerrada la recuperación final de captura con fingerprint funcional versionado,
  binding inmutable, marker durable previo a `O_EXCL`, roots de estado/artifacts
  independientes, doctor Linux sin mutaciones, gramática cerrada de journals e
  inventario que no infiere desconexión ante `iw link` vacío.
- El DEB Linux usa wheelhouse fijado, Pydantic 2 y venv privado offline; doctor
  ejecuta diagnósticos con la identidad allowlisted del servicio.
- Agregadas unidades systemd separadas y endurecidas para endpoint/capture,
  packaging DEB reproducible, lifecycle operativo y validación estática. El
  endpoint no recibe capabilities Linux; Capture Node nunca recibe
  CAP_SYS_ADMIN.
- Agregados Flent condicional y tcpreplay deny-by-default limitado a
  validación/simulación con namespace, scenario, interfaz, límites y hashes
  aprobados. No se ejecuta replay real en Fase 07.
- Endurecido el inventario Windows con siete procesos `powershell.exe`
  explícitos y consultas fijas, sin `Start-Job`, `JobRepository` ni terminación
  por PID. Cada worker publica PID+creation-time antes de una barrera común; el
  coordinador valida esa identidad por su handle estable, lo asigna a un Job
  Object propio y recién entonces libera el provider. Los budgets concurrentes
  de 8/8/5/10/5/5/5 segundos comienzan en un timestamp común y un guard de
  release aborta fail-soft si no caben completos junto con cleanup y ensamblado.
  El reap compartido dispone de 3 segundos más 1 segundo final, observa y
  dispone streams y cierra handles exactamente una vez. El coordinador tiene
  una ventana interna de planificación de 26 segundos, una fase de providers de
  20 segundos y una última barrera dura externa de 30 segundos. El process runner crea cada coordinador
  suspendido, lo asigna a su Job Object antes de `ResumeThread`, y conserva un
  `ProcessContext` por token/identidad de objeto: el PID es sólo metadata.
  El deadline de solicitud comienza antes del spawn y el cleanup tiene 5
  segundos de gracia, con los últimos 100 ms reservados para force-close y
  drenaje. Ready y marker ahora se observan como condiciones independientes:
  ready adelantado espera el consumo y validación del marker hasta el deadline
  de startup, sin recortar ni adelantar los budgets de providers. Los
  diagnósticos continúan exclusivamente por stderr.
- Agregado el adapter Windows de referencia con Native Wi-Fi mediante `ctypes`,
  telemetría normalizada por campo, PowerShell JSON y fallback netsh localizado.
- Agregados control Wi-Fi exclusivamente local y allowlisted, journal SQLite
  schema 2, Windows Service LocalService y named pipe cerrado para enrollment.
- Agregados packaging preliminar PyInstaller onedir y detección diagnóstica de
  Npcap/dumpcap sin captura; iperf3 permanece fuera de Fase 06.
- Endurecidos install/uninstall/upgrade/rollback de Windows con layout canónico,
  TestMode confinado por WorkRoot, rechazo de traversal/reparse points y borrado
  recursivo validado inmediatamente; ampliados los tests del manifest final Windows.
- Agregado el runtime desktop compartido Windows/Linux con configuración TOML
  estricta, SQLite migrable, CLI, heartbeat, Capability Manifest, rotación
  recuperable, scheduler local y TaskRunner.
- Agregados adapters Windows Credential Manager y Linux Secret Service,
  ProcessRunner deny-by-default, plugin sin efectos `protocol.contract_check` y
  simuladores explícitos para CI.
- Empaquetados los contratos del agente como copia derivada verificable de los
  14 schemas, 15 capabilities y 25 fixtures de Fase 04.
- Agregadas suites Linux, property/state-machine, wheel limpio y jobs CI nativos
  Ubuntu/Windows para el agente desktop.

### Added

- Contratos normativos OpenAPI 3.1 y JSON Schema Draft 2020-12, golden
  fixtures compartidos y consumidores ejecutables Python, TypeScript, Kotlin y Swift.
- Enrolamiento single-use, identidad y credentials individuales rotables,
  replay secreto AEAD, revocación inmediata y recovery autorizado.
- Capability Manifest de siete dimensiones, heartbeat desktop, presence mobile,
  agent auth con nonce Redis y stubs protegidos para fases futuras.
- Baseline arquitectónico para el producto inicial `0.1.0`.
- Separación de control, data, telemetry, artifact e integration planes.
- ADRs para stack, contratos, capabilities, delivery, almacenamiento,
  lifecycle móvil, tráfico, tiempo, captura, plugins y deployment.
- Diagramas Mermaid de contexto, componentes, topologías y flujos.
- Threat model inicial y matriz multidimensional de capabilities.
- Reglas conceptuales de métricas, límites, reservas y compatibilidad.
- Monorepo ejecutable de Fase 02 con backend, frontend, worker, reverse proxy,
  PostgreSQL, Redis, artifact store filesystem y agente simulado outbound-only.
- Health/readiness, logs JSON, correlation IDs, scripts equivalentes, tests y
  CI Linux basada en contenedores.
- Dominio persistente de usuarios, roles, permisos, sesiones, refresh tokens y
  auditoría, con esqueletos mínimos para continuidad de fases posteriores.
- JWT HS256 estricto, Argon2id, refresh rotation/reuse detection, revocación,
  RBAC deny-by-default, rate limiting Redis y protección CSRF same-origin.
- Seeds idempotentes, bootstrap seguro del primer administrador, roles de base
  separados, migraciones reproducibles y tests PostgreSQL/Redis reales.

### Changed

- `docs/architecture/` pasa a ser la ubicación canónica de arquitectura.
- README actualizado para reflejar versiones, prioridades y restricciones.
- Alineado el contexto normativo maestro con los ADRs aceptados: `reason` es el
  único nombre conceptual para explicar indisponibilidad, condicionamiento,
  degradación o decisiones de ejecución; `value: null` nunca significa cero.
- Separadas las dimensiones conceptuales del capability manifest en
  `technical_support`, `implementation_status`, `permission_requirement`,
  `user_interaction`, `background_execution`, `provider` y `limitations`, sin
  cerrar vocabularios ni JSON Schema antes de la Fase 04.
- Alineados los ejemplos de capability IDs con el baseline conceptual aprobado.
- Alineadas las instrucciones específicas de `prompts/` con el contexto
  normativo raíz y los ADRs aceptados.
- Corregido el Prompt 04 para alinear capability manifests, IDs canónicos,
  versionado, idempotencia, autoridad contractual, consumidores y tratamiento
  de credenciales con el baseline normativo aprobado.
- Excluidas de Black únicamente las migraciones publicadas 0001–0003; smoke usa
  un project name aislado, restaura el entorno y verifica cleanup de recursos.
- Reforzada la evidencia del consumidor Swift con compilación y validación
  Codable/semántica explícita de los 25 golden fixtures compartidos.
- Corregida la inclusión exclusiva del Gradle Wrapper JAR de Kotlin, con hash y
  guardrail Git; documentado el inventario contractual exacto de 14 schemas.
- Documentado el flujo local Windows/WSL2 y Linux, troubleshooting, rollback y
  mapa del monorepo.

### Security

- Documentados controles para enrolamiento, credenciales, leases,
  idempotencia, tráfico autorizado, captura, plugins y cambios de
  infraestructura.
- PostgreSQL, Redis y servicios internos no publican puertos; el reverse proxy
  no privilegiado es el único ingreso normal del entorno local.
- Secretos locales independientes se generan en `.env` ignorado; los ejemplos
  no contienen valores utilizables. AuditLog es append-only para aplicación y
  rol runtime, sin afirmar inmutabilidad frente al propietario PostgreSQL.
- El upgrade `--add-missing` agrega sólo las claves secretas de Fase 04 mediante
  CSPRNG, preserva valores existentes y mantiene `--force` como rotación
  destructiva separada.

## Release status

No se publicó todavía una versión funcional ni se creó un tag de release.
