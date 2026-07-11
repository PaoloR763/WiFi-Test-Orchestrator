# ADR-0006: Cola de ejecución persistente y abstracción de workers

## Status

Accepted

## Context

El orquestador debe entregar tareas a agentes Windows, Linux, Android e iOS sin conexiones entrantes hacia ellos. También debe ejecutar trabajo interno asíncrono, como scheduling, consolidación de resultados, retención y renderizado de reportes. Reinicios, particiones de red, suspensión de dispositivos móviles y reintentos pueden producir entregas duplicadas o interrumpidas.

Una cola mantenida sólo en memoria perdería trabajo aceptado. Usar el broker como única fuente de verdad acoplaría el dominio a una tecnología y dificultaría reconstruir el estado después de una pérdida de mensajes. A su vez, prometer ejecución exactly-once sería incorrecto: un proceso puede completar un efecto y fallar antes de confirmar su resultado.

## Decision

- PostgreSQL será la fuente de verdad transaccional para tareas, ejecuciones, transiciones de estado, intentos, expiración, auditoría y resultados aceptados.
- La aceptación de trabajo y la intención de publicarlo se guardarán en una única transacción mediante un patrón transactional outbox o mecanismo equivalente. Un reconciliador podrá volver a publicar trabajo pendiente a partir del estado durable.
- Redis se usará para coordinación, locks, rate limits y transporte de cola. Celery será el adapter inicial de workers, pero el dominio dependerá de una interfaz `ExecutionBackend`, no de primitivas ni objetos de Celery.
- La semántica será at-least-once. Cada tarea tendrá UUID, `schema_version`, tipo y versión, parámetros validados, expiración, `idempotency_key`, capacidades requeridas y correlation ID. Los handlers deberán ser idempotentes o registrar de forma durable sus efectos antes de confirmar.
- La asignación a un agente se realizará mediante un lease renovable. El lease identifica al propietario temporal y evita ejecución concurrente intencional; su vencimiento permite recuperar trabajo abandonado. Un lease no elimina la obligación de idempotencia.
- La entrega base será HTTPS outbound-only iniciado por el agente. El agente recuperará trabajo, lo persistirá localmente antes de confirmar recepción y mantendrá en SQLite o Room el inbox, checkpoints y outbox de resultados necesarios para sobrevivir a reinicios.
- Un resultado se eliminará de la cola local sólo después de una confirmación durable e idempotente del servidor. Repetir una entrega o un resultado con la misma identidad no deberá repetir efectos ni crear ejecuciones históricas distintas.
- Las tareas expiradas no se iniciarán. La recuperación tras pérdida de lease, reintentos y cancelaciones conservará el historial de intentos y una razón estructurada.
- Los procesos de API, scheduler, dispatcher, worker y reconciliación podrán escalar o reiniciarse por separado, aunque el MVP se despliegue sin alta disponibilidad.

## Consequences

- El trabajo aceptado puede reconstruirse desde PostgreSQL aun si Redis o un worker pierden estado.
- Los agentes toleran desconexiones y reinicios sin depender de una conexión inbound ni de memoria volátil.
- Los adapters de ejecución pueden cambiar sin alterar el modelo de dominio ni los contratos servidor-agente.
- Se requieren reconciliadores, limpieza de outbox, métricas de queue lag, leases vencidos, reintentos y dead-letter state.
- Los plugins y handlers deben diseñarse para reentrada; los efectos externos no idempotentes necesitan deduplicación o compensación explícita.
- PostgreSQL recibe más escrituras de control, por lo que deberán medirse contención, crecimiento del historial y políticas de retención.

## Alternatives considered

- **Cola en memoria:** se descarta porque pierde trabajo en reinicios y no permite auditoría ni recuperación confiable.
- **Redis o Celery como única fuente de verdad:** se descarta porque mezcla transporte con estado transaccional y dificulta la reconciliación.
- **Acoplar el dominio directamente a Celery:** se descarta porque impide sustituir el worker sin propagar cambios al núcleo.
- **Push directo o conexión permanente como canal autoritativo:** se descarta por el modelo outbound-only y por las restricciones de lifecycle móvil.
- **Garantía exactly-once:** se descarta porque no puede sostenerse de extremo a extremo frente a fallas entre el efecto y su confirmación.

## Deferred decisions

- Duración y política de renovación de leases.
- Algoritmo de retry, backoff, jitter y clasificación definitiva de errores.
- Configuración concreta de Redis, Celery, prioridades, particiones y dead-letter processing.
- Estrategia de long polling y cadencia de recuperación por plataforma.
- Nombres finales de estados y formato de los contratos públicos, que se definirán con JSON Schema y contract tests.

## References

- [AGENTS.md](../../../AGENTS.md), secciones 3, 6, 8 y 9.
- [Prompt 01 - Arquitectura, ADRs y modelo de amenazas](../../../prompts/01_architecture_and_adrs.md).
- [ADR-0008: Lifecycle móvil y push sólo como aviso](0008-mobile-lifecycle-and-notification-only-push.md).
- [ADR-0010: Providers de tráfico y reservas emitidas por el servidor](0010-traffic-providers-and-server-issued-reservations.md).
