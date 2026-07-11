# ADR-0005: Outbound task delivery, leases and idempotency

## Status

Accepted

## Context

Los agentes se ejecutan detrás de NAT, firewalls y políticas mobile que impiden
suponer conectividad inbound o ejecución inmediata. Pueden desconectarse entre
la recepción y la finalización de una tarea. Los workers también pueden fallar,
y una reentrega no debe duplicar efectos, consumo de ancho de banda ni cambios
de infraestructura.

FCM y APNs pueden mejorar el tiempo de reacción de una aplicación mobile, pero
no garantizan entrega, wake-up ni ejecución en background. Tampoco deben
convertirse en un canal de control con autoridad propia.

## Decision

La entrega base será outbound-only. Cada agente iniciará conexiones HTTPS al
servidor, se autenticará con su identidad individual y recuperará trabajo desde
la API. TLS será obligatorio fuera de desarrollo. El servidor no abrirá una
consola ni ejecutará shell remoto arbitrario en los agentes.

FCM y APNs se usarán únicamente como avisos. Un aviso no será una tarea, no
transportará secretos ni parámetros autoritativos y no habilitará ejecución por
sí mismo. Después del aviso, el agente deberá recuperar y validar la tarea por
HTTPS. Si el lifecycle de Android o iOS no permite hacerlo a tiempo, el sistema
registrará el resultado explicable correspondiente en vez de prometer ejecución
inmediata.

Una tarea incluirá conceptualmente UUID, tipo, `schema_version`, parámetros
validados, expiración, `idempotency_key` y capabilities requeridas. Este ADR no
fija su JSON Schema ni formatos finales.

PostgreSQL conservará la verdad transaccional de tareas, asignaciones y
resultados. Redis se usará para cola, coordinación, locks y rate limits detrás
de una interfaz de ejecución. El agente mantendrá en SQLite el estado necesario
para sobrevivir reinicios, continuar uploads y reconocer trabajo ya procesado.
La pérdida de un elemento efímero de Redis no debe redefinir la historia
transaccional.

La entrega usará leases:

- El agente reclama una tarea mediante una operación atómica del servidor.
- El lease concede autoridad exclusiva y acotada para esa asignación, no una
  autorización general para ejecutar comandos.
- Una ejecución activa puede renovar su lease mientras sigue siendo válida.
- Al expirar un lease sin terminal result, el servidor puede volver a ofrecer el
  trabajo según su policy.
- El servidor rechaza resultados que no puedan relacionarse con la task, el
  agente y la asignación correspondientes.

No se presume exactly-once delivery. La infraestructura tolerará reintentos y
reentregas; la corrección se obtendrá con idempotencia, validación de estado y
registro persistente. Una misma operación lógica conservará su
`idempotency_key`. El servidor y el agente detectarán duplicados y reutilizarán
el resultado terminal registrado cuando sea válido, en vez de iniciar otra vez
el mismo efecto. El scope y la retención exactos de la clave se definirán en el
contrato.

Toda prueba de tráfico requerirá una reserva emitida por el servidor antes de
ejecutarse. La reserva vinculará conceptualmente la ejecución y el agente con
destinos autorizados, dirección, protocolo y límites efectivos de duración,
ancho de banda, streams, tamaño y concurrencia que correspondan. Un límite
solicitado `null` hereda policy; nunca significa ilimitado. La tarea no podrá
iniciar mientras un límite efectivo o el destino autorizado permanezcan sin
resolver.

Los plugins y comandos ejecutables deberán estar registrados en una allowlist
firmada y versionada. La posesión de una task o un lease no permite saltar esa
verificación, ampliar una reserva ni acceder a destinos arbitrarios.

El enrolamiento usará un token de un solo uso para emitir credenciales
individuales revocables y rotables. La arquitectura podrá evolucionar a mTLS sin
cambiar el principio outbound-only. Los formatos de credenciales y mecanismos
criptográficos se definirán en una decisión de seguridad posterior.

Todos los eventos de entrega y ejecución se correlacionarán y fecharán en UTC,
con offset, incertidumbre y drift cuando correspondan, de acuerdo con ADR-0003.

## Consequences

- No es necesario exponer puertos de agentes ni mantener rutas inbound a redes
  de laboratorio.
- Las desconexiones y reinicios pueden recuperarse sin perder trazabilidad.
- Una tarea puede entregarse más de una vez, por lo que cada handler con efectos
  debe implementar idempotencia real.
- La ejecución mobile puede quedar demorada, `SKIPPED` o `BLOCKED` por lifecycle,
  permisos o interacción; el aviso push no cambia esa realidad.
- PostgreSQL, Redis y SQLite deben reconciliar estados después de fallas
  parciales.
- Las reservas reducen el riesgo de tráfico no autorizado, pero exigen validar
  destino y límites tanto al emitir como al ejecutar.
- Leases demasiado breves o prolongados pueden producir churn o recuperación
  lenta, por lo que requieren medición antes de fijar TTL.

## Alternatives considered

- **Conexiones inbound o remote shell hacia agentes:** descartadas por seguridad,
  NAT, firewalls y portabilidad.
- **Transportar tareas completas por FCM/APNs:** descartado porque push no es un
  canal confiable ni autoritativo y puede exponer datos sensibles.
- **Fire-and-forget sin lease:** descartado porque no permite recuperar trabajo
  ni controlar ejecución concurrente.
- **Prometer exactly-once delivery:** descartado porque no puede garantizarse a
  través de fallas distribuidas; se adopta reentrega idempotente.
- **Usar Redis como única fuente de verdad:** descartado porque su rol es
  coordinación y cola, no historia transaccional.
- **Interpretar límites nulos como ilimitados:** descartado porque eludiría
  policies y controles de seguridad.

## Deferred decisions

- JSON Schemas, endpoints y representación final de tasks, leases, resultados y
  reservas.
- TTL de task, lease, reservation, credential e idempotency record.
- Vocabularios de estados, códigos de `reason` y reglas finales de transición.
- Estrategia de polling, backoff, jitter, long polling o transporte equivalente.
- Configuración de persistencia de Redis y algoritmo de reconciliación con
  PostgreSQL y SQLite.
- Scope, retención y respuesta exacta ante colisiones de `idempotency_key`.
- Representación y validación de destinos, resolución DNS y binding de reservas.
- Formato de firma, algoritmos criptográficos, trust distribution y revocación.
- Integración concreta con FCM/APNs y políticas de ejecución offline/mobile.
- Flujo detallado de enrolamiento, rotación y futura adopción de mTLS.

## References

- [AGENTS.md, secciones 2, 3, 6 y 9](../../../AGENTS.md)
- [ADR-0001: Technology stack and portable OCI deployment](0001-technology-stack-and-portable-oci-deployment.md)
- [ADR-0002: Domain and plane boundaries](0002-domain-and-plane-boundaries.md)
- [ADR-0003: Contract versioning and compatibility](0003-contract-versioning-and-compatibility.md)
- [ADR-0004: Capability-driven platform model](0004-capability-driven-platform-model.md)
