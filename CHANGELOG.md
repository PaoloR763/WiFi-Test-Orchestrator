# Changelog

Todos los cambios relevantes de WiFi Test Orchestrator se documentarán en este
archivo.

El formato se inspira en Keep a Changelog y el producto utilizará Semantic
Versioning cuando existan releases publicadas.

## Unreleased

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
