# Architecture Decision Records

Este directorio es la ubicación canónica de los Architecture Decision Records
(ADRs) de WiFi Test Orchestrator. `AGENTS.md` es la autoridad normativa global;
los ADRs aceptados especializan esas reglas para decisiones arquitectónicas
concretas y no pueden contradecirlas.

La línea base documentada corresponde al producto `0.1.0`. La prosa funcional
se mantiene en español y los identificadores técnicos, nombres de componentes e
interfaces se mantienen en inglés.

## Índice

| ADR | Título | Status | Propósito |
| --- | --- | --- | --- |
| [0001](0001-technology-stack-and-portable-oci-deployment.md) | Technology stack and portable OCI deployment | Accepted | Fijar el stack y la portabilidad del despliegue sin dependencias del host Windows. |
| [0002](0002-domain-and-plane-boundaries.md) | Domain and plane boundaries | Accepted | Separar responsabilidades, datos y flujos entre los cinco planos. |
| [0003](0003-contract-versioning-and-compatibility.md) | Contract versioning and compatibility | Accepted | Establecer las líneas base y reglas de evolución de los contratos compartidos. |
| [0004](0004-capability-driven-platform-model.md) | Capability-driven platform model | Accepted | Modelar soporte real y disponibilidad sin asumir paridad entre plataformas. |
| [0005](0005-outbound-task-delivery-leases-and-idempotency.md) | Outbound task delivery, leases and idempotency | Accepted | Definir la entrega segura y recuperable de tareas iniciada por los agentes. |
| [0006](0006-persistent-execution-queue-and-worker-abstraction.md) | Persistent execution queue and worker abstraction | Accepted | Mantener trabajo durable sin acoplar el dominio al broker o worker. |
| [0007](0007-transactional-local-and-artifact-storage.md) | Transactional, local and artifact storage | Accepted | Asignar responsabilidades a PostgreSQL, Redis, SQLite y artifact storage. |
| [0008](0008-mobile-lifecycle-and-notification-only-push.md) | Mobile lifecycle and notification-only push | Accepted | Respetar lifecycle móvil y limitar push a avisos no autoritativos. |
| [0009](0009-agent-enrollment-identity-and-credential-rotation.md) | Agent enrollment, identity and credential rotation | Accepted | Emitir identidades individuales revocables y preparar evolución a mTLS. |
| [0010](0010-traffic-providers-and-server-issued-reservations.md) | Traffic providers and server-issued reservations | Accepted | Separar función/provider y exigir reservas y límites efectivos. |
| [0011](0011-metric-envelope-null-semantics-and-comparability.md) | Metric envelope, null semantics and comparability | Accepted | Preservar procedencia, ausencia real y comparabilidad de métricas. |
| [0012](0012-time-quality-and-cross-plane-correlation.md) | Time quality and cross-plane correlation | Accepted | Registrar calidad temporal para correlaciones honestas. |
| [0013](0013-capture-and-replay-isolation.md) | Capture and replay isolation | Accepted | Aislar captura y replay según rol, hardware, alcance y autorización. |
| [0014](0014-plugin-trust-and-extensibility.md) | Plugin trust and extensibility | Accepted | Extender mediante plugins verificados sin habilitar ejecución arbitraria. |
| [0015](0015-mvp-topologies-capacity-and-recovery.md) | MVP topologies, capacity and recovery | Accepted | Fijar topologías y supuestos iniciales revisables del MVP. |

## Convenciones

- Cada ADR contiene `Status`, `Context`, `Decision`, `Consequences`,
  `Alternatives considered`, `Deferred decisions` y `References`.
- `Accepted` indica que la decisión rige para el alcance documentado. Un cambio
  incompatible requiere un ADR posterior que preserve la trazabilidad; no se
  reescribe silenciosamente la decisión histórica.
- Los identificadores de capabilities incluidos en esta fase son conceptuales y
  no sustituyen los futuros OpenAPI, JSON Schemas ni contract tests.
- Las representaciones finales, vocabularios cerrados, TTL, algoritmos y formatos
  criptográficos se deciden en las fases de contratos y seguridad
  correspondientes.
- Los ejemplos JSON existentes son ilustrativos y no normativos.

## References

- [AGENTS.md](../../../AGENTS.md)
- [Prompt 01 - Arquitectura, ADRs y modelo de amenazas](../../../prompts/01_architecture_and_adrs.md)
