# AGENTS.md - Contexto maestro de WiFi Test Orchestrator

Actuá como arquitecto de software senior, desarrollador full stack, especialista en redes Wi-Fi IEEE 802.11, automatización de pruebas, aplicaciones móviles, sistemas distribuidos y seguridad.

## 1. Propósito

Construir una plataforma original para automatizar, ejecutar, observar y administrar pruebas Wi-Fi en laboratorios, pilotos y redes autorizadas. La solución puede inspirarse en capacidades generales de plataformas profesionales de testing, pero no debe copiar código, interfaces, nombres internos, documentación confidencial ni procesos propietarios de DEKRA, Wi-Fi Alliance u otros proveedores.

El producto debe permitir:

- Inventariar agentes, dispositivos de infraestructura y bancos de prueba.
- Ejecutar pruebas repetibles de conectividad, latencia, throughput, estabilidad y comportamiento de aplicaciones.
- Generar tráfico sintético controlado mediante proveedores intercambiables.
- Correlacionar resultados del endpoint con telemetría de AP, gateway, controlador o Capture Node.
- Gestionar casos, suites, planes, campañas, thresholds, artefactos y reportes.
- Conservar trazabilidad suficiente para comparar hardware, firmware, drivers, sistemas operativos y configuraciones.

## 2. Alcance de plataformas

### Servidor

- Desarrollo y despliegue inicial en Windows 11 con Docker Desktop y WSL2.
- Servicios ejecutados como contenedores Linux OCI.
- Portabilidad obligatoria a Linux, macOS y entornos cloud sin cambiar el dominio ni los contratos.
- No depender de rutas, servicios o APIs exclusivas del host Windows.

### Agentes

- Windows 10/11: agente desktop como Windows Service.
- Linux: agente desktop como servicio systemd y rol opcional de Capture Node.
- Android: aplicación nativa Kotlin, con Activity, Foreground Service y WorkManager según el lifecycle permitido.
- iOS/iPadOS: aplicación nativa Swift, foreground-first; BackgroundTasks, URLSession background y APNs solo como mecanismos permitidos y no como garantía de ejecución inmediata.

No asumir paridad de capacidades entre plataformas. El servidor debe usar un modelo capability-driven y explicar SKIPPED/BLOCKED cuando una función no exista o requiera interacción.

## 3. Arquitectura obligatoria

- Backend: Python 3.12+, FastAPI, SQLAlchemy 2, Alembic, Pydantic 2.
- PostgreSQL como fuente de verdad transaccional.
- Redis para coordinación, locks, rate limits y cola.
- Celery u otro worker compatible detrás de una interfaz de ejecución.
- Frontend React + TypeScript + Vite.
- Agentes Windows/Linux en Python con SQLite local y adaptadores por OS.
- Android en Kotlin, Jetpack, Room, WorkManager, Retrofit/OkHttp y APIs de red nativas.
- iOS en Swift/SwiftUI, URLSession, Network.framework, BackgroundTasks y Keychain.
- Contratos compartidos mediante OpenAPI, JSON Schema, ejemplos y contract tests; no compartir runtime a la fuerza.
- Artefactos detrás de una abstracción compatible con filesystem local y S3/MinIO.
- Comunicación outbound-only desde agentes hacia el servidor mediante HTTPS.

## 4. Separación de dominios

Mantener límites explícitos entre:

1. Control plane: usuarios, agentes, inventario, campañas, scheduling, políticas y auditoría.
2. Data plane de pruebas: tráfico generado entre endpoints y servidores de prueba autorizados.
3. Telemetry plane: muestras periódicas, eventos, availability y metadatos de medición.
4. Artifact plane: logs, PCAP/PCAPNG, JSON crudo, CSV, reportes y hashes.
5. Integration plane: adaptadores de AP, gateway, ONT, controlador, SNMP, TR-181/USP o APIs externas.

## 5. Motor de pruebas y tráfico

No acoplar el producto a iperf3. Definir interfaces versionadas:

- `TestPlugin`
- `TrafficGenerator`
- `LatencyProbe`
- `CaptureProvider`
- `InfrastructureAdapter`
- `ReportRenderer`

Proveedores iniciales:

- iperf3 para TCP/UDP en Windows/Linux.
- HTTP upload/download con timings en todas las plataformas.
- Sockets TCP/UDP nativos para Android/iOS y fallback desktop.
- Ping ICMP donde sea posible; TCP/HTTP latency donde no lo sea.
- Latency-under-load combinando generador de tráfico y probe independiente.
- Flent opcional en Linux/desktop para pruebas agregadas de bufferbloat.
- Tcpreplay únicamente en nodos Linux especializados, con allowlist, aislamiento y redes autorizadas.

Todos los resultados deben conservar proveedor, versión, método, dirección, protocolo, streams, bitrate solicitado, límites, servidor, timestamps, capacidad disponible y contexto de plataforma.

## 6. Reglas de seguridad

- Uso exclusivo en redes y dispositivos autorizados.
- Prohibido implementar shell remoto arbitrario.
- Cada plugin y comando debe estar registrado en una allowlist firmada/versionada.
- Las tareas deben incluir UUID, tipo, versión de esquema, parámetros validados, expiración, idempotency key y capacidades requeridas.
- TLS obligatorio fuera de desarrollo; autenticación individual por agente; revocación y rotación.
- Secretos cifrados y nunca visibles en logs, excepciones, reportes o telemetría.
- RBAC mínimo: Administrator, Test Manager, Operator, Viewer y Agent.
- Auditoría inmutable para acciones sensibles.
- Rate limits, cuotas, límites de duración, ancho de banda, concurrencia y destino para generación de tráfico.
- Capturas limitadas por tiempo, tamaño, interfaz y filtro; sin descifrado o evasión de sandbox/permisos.
- Tcpreplay no debe estar disponible para endpoints comunes ni para destinos arbitrarios.
- Toda modificación de infraestructura requiere snapshot previo, permisos específicos, validación y rollback.

## 7. Fidelidad técnica Wi-Fi

- No inventar métricas. `value: null` nunca significa cero.
- Toda métrica usa conceptualmente `value`, `unit`, `source`, `availability`, `confidence` y `reason`.
- `reason` es el único nombre conceptual para explicar indisponibilidad, condicionamiento, degradación o una decisión de ejecución; no definir un campo paralelo `availability_reason`.
- La cardinalidad, las enumeraciones y la representación JSON final de `reason` se definirán en la Fase 04.
- Diferenciar telemetría del SO, contadores de interfaz, captura IP, captura 802.11 y telemetría de infraestructura.
- Un endpoint no observa todas las tramas de terceros.
- Roaming medido por endpoint es observado/inferido salvo captura sincronizada.
- iOS no debe prometer scan genérico de redes, monitor mode, daemon permanente, RSSI universal ni control arbitrario de perfiles.
- Android debe respetar permisos runtime, scan throttling, foreground service restrictions y APIs soportadas de Suggestion/Specifier.
- Las comparaciones deben indicar si los métodos son equivalentes, aproximados o no comparables.

## 8. Modelo de capacidades

Cada agente publica un manifiesto versionado con:

- capability id y versión.
- soporte técnico (`technical_support`).
- estado de implementación (`implementation_status`).
- requisitos de permisos o entitlements (`permission_requirement`).
- interacción de usuario (`user_interaction`).
- ejecución en foreground/background y restricciones de lifecycle (`background_execution`).
- proveedor y versión (`provider`).
- límites de duración, throughput, tamaño, concurrencia y demás condiciones (`limitations`).

Estas dimensiones no se condensan en un único campo `support`. `reason` es el único nombre conceptual para explicar indisponibilidad, condicionamiento, degradación o una decisión de ejecución. Los vocabularios cerrados y el JSON Schema del manifiesto se definirán en la Fase 04.

Ejemplos: `wifi.connection.read`, `wifi.scan`, `wifi.rssi.read`, `network.icmp.ping`, `network.tcp.probe`, `network.http.probe`, `traffic.tcp.throughput`, `traffic.udp.throughput`, `traffic.http.download`, `traffic.http.upload`, `traffic.latency_under_load`, `capture.ip`, `capture.ieee80211.monitor`, `traffic.pcap.replay`, `execution.background.continuous`.

## 9. Contratos y compatibilidad

- Versionar OpenAPI y JSON Schemas.
- Usar `schema_version` en mensajes persistidos o enviados.
- Cambios aditivos por defecto.
- Cambios incompatibles requieren nueva versión, migración y ventana de compatibilidad.
- Mantener golden test vectors y contract tests para Python, TypeScript, Kotlin y Swift.
- No cambiar semántica histórica al modificar thresholds o plugins.
- Cada ejecución conserva snapshot inmutable de parámetros, thresholds, manifests y versiones.

## 10. Calidad y documentación

- Código y nombres técnicos en inglés; documentación funcional principal en español.
- Type hints, validación estricta, errores estructurados y correlation IDs.
- Tests unitarios, integración, contrato, E2E, resiliencia y seguridad.
- Linters: Ruff/Black/MyPy, ESLint/Prettier, ktlint/detekt, SwiftLint.
- Cada feature actualiza README, referencia de API, troubleshooting y changelog.
- Mantener ADRs, diagramas Mermaid, runbooks, matriz de compatibilidad y guía de extensión.
- Timestamps UTC en persistencia; zona local solo en presentación.

## 11. Forma de trabajo con Codex

Antes de editar:

1. Leer este archivo, ADRs, contratos, migraciones, ejemplos y tests relacionados.
2. Resumir el estado actual y contradicciones.
3. Proponer un plan breve con archivos y riesgos.
4. Implementar código completo; evitar pseudocódigo y stubs silenciosos.
5. Ejecutar lint, type checking, tests y migraciones aplicables.
6. Corregir fallas antes de finalizar.
7. Entregar evidencia de comandos, archivos modificados, decisiones y limitaciones.

No modificar contratos públicos sin actualizar consumidores, esquemas, migraciones, documentación y tests. Los mocks se permiten en tests y simuladores, nunca para ocultar funcionalidad faltante en producción.

## 12. Definición de terminado

Una tarea está terminada cuando:

- Compila/inicia en la plataforma objetivo.
- Las migraciones aplican desde una base vacía y desde la versión anterior soportada.
- Tests y linters pasan.
- Hay criterios de aceptación verificables.
- Se documentaron configuración, seguridad, observabilidad, rollback y limitaciones.
- No se incluyeron secretos, binarios no verificados ni archivos temporales.
- El cambio es compatible con la estrategia de versionado y extensión.
