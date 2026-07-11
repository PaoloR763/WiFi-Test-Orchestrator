# Arquitectura del sistema

## Propósito

WiFi Test Orchestrator coordina pruebas autorizadas sin convertir los agentes
en consolas remotas. El servidor decide qué trabajo puede ejecutarse; cada
agente publica sus condiciones reales y sólo ejecuta acciones registradas y
validadas.

Diagramas relacionados:

- [System context](diagrams/01-system-context.mmd)
- [Container view](diagrams/02-container-view.mmd)
- [Server component view](diagrams/03-server-component-view.mmd)
- [Agent component view](diagrams/04-agent-component-view.mmd)
- [Planes and trust boundaries](diagrams/05-plane-and-trust-boundary-flow.mmd)

## Contexto

Los actores principales son:

- `Administrator`, `Test Manager`, `Operator` y `Viewer`, mediante el
  frontend y la API.
- Agentes Windows, Linux, Android e iOS.
- Agentes simulados para desarrollo y contract tests futuros.
- Traffic Nodes autorizados para recibir o generar tráfico de prueba.
- Capture Nodes Linux especializados.
- APs, gateways, ONTs y controladores mediante adapters controlados.
- FCM y APNs como canales de aviso, nunca como transporte de tareas.

La comunicación entre agentes y servidor es outbound-only y se inicia por
HTTPS desde el agente. El data plane de una prueba sólo utiliza destinos y
límites materializados por una reserva emitida por el servidor.

## Planos

| Plano | Responsabilidades | Fuente de verdad o evidencia | No debe asumir |
|---|---|---|---|
| Control plane | Usuarios, RBAC, inventario, agentes, campañas, scheduling, políticas, reservas y auditoría | PostgreSQL y audit trail | Que una capability declarada esté disponible ahora |
| Data plane | Tráfico sintético entre endpoints y servidores autorizados | Resultado crudo, provider y reserva | Acceso a destinos arbitrarios |
| Telemetry plane | Muestras, eventos, availability y calidad temporal | Series detalladas y agregadas | Que `null` sea cero o que las fuentes sean equivalentes |
| Artifact plane | Logs, JSON crudo, CSV, reportes y PCAP/PCAPNG | Artifact store más hash y metadatos transaccionales | Que un artefacto sea confiable sin integridad y autorización |
| Integration plane | Lectura o cambio controlado de AP, gateway, ONT y controlador | Snapshots, resultados del adapter y auditoría | Shell arbitrario ni cambios sin rollback |

Las fronteras son lógicas incluso cuando varios componentes comparten un host
en el MVP. Un componente no obtiene privilegios de otro plano por estar en el
mismo deployment.

## Contenedores lógicos

| Contenedor | Responsabilidad | Dependencias permitidas |
|---|---|---|
| Web frontend | Operación, observación y administración según RBAC | API `v1` por HTTPS |
| API service | Validación, autenticación, control de acceso y recursos de dominio | PostgreSQL, Redis y servicios internos |
| Scheduler/orchestrator | Selección de agentes, políticas, campañas y creación de tareas | Estado transaccional y manifest snapshots |
| Execution worker | Trabajo asíncrono detrás de una interfaz reemplazable | Cola coordinada, base transaccional y adapters registrados |
| Telemetry ingestion | Recepción, validación y persistencia de muestras y eventos | PostgreSQL o almacenamiento especializado futuro |
| Artifact service | Upload, integridad, metadatos y abstracción local/S3 | Artifact store y PostgreSQL |
| Integration adapters | Operaciones allowlisted sobre infraestructura | APIs o protocolos explícitos, secretos protegidos |
| Notification adapter | Avisos FCM/APNs sin payload de tarea ni secretos | Proveedores externos de push |
| PostgreSQL | Verdad transaccional | Backup y restauración documentados |
| Redis | Coordinación, locks, rate limits y entrega de trabajo | Estado durable reconstruible o respaldado por PostgreSQL |
| Artifact store | Bytes de artefactos | Filesystem en desarrollo; S3/MinIO mediante abstracción |

La tecnología obligatoria del servidor es Python 3.12+, FastAPI, SQLAlchemy
2, Alembic y Pydantic 2. El frontend utilizará React, TypeScript y Vite. Estas
elecciones no implican que esos runtimes se creen en esta fase documental.

## Componentes del servidor

- `Identity and RBAC`: usuarios, sesiones, roles y políticas.
- `Agent Registry`: identidad, credenciales, revocación y manifests.
- `Inventory`: dispositivos, bancos, traffic nodes y capture nodes.
- `Capability Matcher`: evalúa dimensiones y restricciones sin reducirlas a
  un único estado.
- `Campaign Planner`: casos, suites, planes, campañas y snapshots.
- `Task Service`: tareas inmutables, idempotencia, expiración y outcomes.
- `Lease Service`: adquisición, renovación, fencing y recuperación.
- `Reservation Service`: autoriza destinos y materializa límites efectivos.
- `Execution Queue`: entrega persistente detrás de una interfaz de worker.
- `Telemetry Service`: muestras, eventos, availability y calidad temporal.
- `Result Service`: resultados, thresholds versionados y comparabilidad.
- `Artifact Service`: uploads, hashes, retención y autorización.
- `Plugin Registry`: manifiestos, allowlist, confianza y revocación.
- `Infrastructure Adapter Registry`: adapters y operaciones registradas.
- `Audit Service`: acciones sensibles y evidencia inmutable en términos del
  dominio; el mecanismo final se definirá en fases posteriores.

## Componentes del agente

- `Agent Core`: lifecycle, configuración, identidad y capabilities.
- `Delivery Client`: polling HTTPS, avisos, leases e idempotencia.
- `Local Queue`: persistencia SQLite para ejecución y reintentos.
- `Policy Guard`: verifica expiración, reserva, límites, destino y plugin.
- `Plugin Runtime`: invoca únicamente plugins y comandos allowlisted.
- `OS Adapter`: APIs específicas de Windows o Linux.
- `Mobile Lifecycle Adapter`: Activity/Foreground Service/WorkManager o
  SwiftUI/BackgroundTasks/URLSession según plataforma.
- `Telemetry Collector`: fuentes del SO, interfaz y ejecución.
- `Time Quality Estimator`: offset, incertidumbre y drift observados.
- `Artifact Uploader`: upload reanudable o diferido mediante HTTPS.

No existe un componente de shell remoto ni una ruta genérica para ejecutar
comandos enviados por el servidor.

## Interfaces de extensión

Las extensiones se incorporarán detrás de interfaces versionadas:

- `TestPlugin`
- `TrafficGenerator`
- `LatencyProbe`
- `CaptureProvider`
- `InfrastructureAdapter`
- `ReportRenderer`

Una capability describe intención funcional. Un provider declara qué
capabilities implementa. Por ejemplo:

```yaml
provider_id: traffic-provider-iperf3
implements:
  - traffic.tcp.throughput
  - traffic.udp.throughput
```

Este fragmento es conceptual, no un manifiesto normativo.

## Ownership de datos

| Dato | Owner lógico | Regla principal |
|---|---|---|
| Identidad y revocación de agente | Agent Registry | Credencial individual y rotable |
| Capability manifest | Agent Registry | Snapshot versionado, no promesa universal |
| Tarea | Task Service | Inmutable después de emitida |
| Lease | Lease Service | Estado separado de la tarea y protegido contra workers obsoletos |
| Reserva de tráfico | Reservation Service | Vinculada a ejecución, agente, destino y límites |
| Telemetría | Telemetry Service | Cada métrica conserva procedencia y availability |
| Resultado | Result Service | Snapshot de parámetros, thresholds, manifest y provider |
| Artefacto | Artifact Service | Bytes fuera del dominio transaccional; hash y metadata dentro |
| Plugin | Plugin Registry | Identidad, versión, integridad, confianza y revocación |
| Cambio de infraestructura | Adapter Registry | Snapshot previo, autorización, validación y rollback |

## Reglas de flujo entre planos

1. El control plane puede autorizar una prueba, pero no transportar su tráfico.
2. El data plane no decide identidades, RBAC ni políticas.
3. Telemetry y artifacts se correlacionan por identificadores y tiempo; no se
   fusionan fuentes como si fueran equivalentes.
4. Integration adapters reciben operaciones tipadas y allowlisted.
5. Redis puede acelerar coordinación, pero no reemplaza el registro
   transaccional requerido para recuperación.
6. Push puede despertar o avisar a una aplicación, pero el agente recupera la
   tarea por HTTPS y vuelve a validar su vigencia.

## Portabilidad

El desarrollo inicial ocurre en Windows 11 con Docker Desktop y WSL2, pero los
servicios del servidor se ejecutarán como contenedores Linux OCI. Configuración,
volúmenes, networking y contratos no contendrán rutas ni APIs exclusivas del
host. `C:\Dev` es sólo la ubicación actual del repositorio.
