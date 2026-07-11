# ADR-0012: Time quality and cross-plane correlation

## Status

Accepted

## Context

Una ejecución combina tareas del control plane, tráfico del data plane, muestras del telemetry plane, artefactos y observaciones de infraestructura. Esos datos se originan en relojes distintos y pueden atravesar colas, reconexiones o cargas diferidas. La coincidencia de timestamps UTC no demuestra por sí sola simultaneidad ni causalidad.

Los agentes móviles pueden suspenderse, los equipos pueden corregir su reloj y los Capture Nodes pueden tener una fuente temporal diferente. Sin información de calidad temporal, la plataforma podría atribuir a una misma ventana eventos que en realidad no son correlacionables.

## Decision

Todos los timestamps persistidos se normalizarán a UTC. La zona horaria local se usará sólo para presentación y nunca para ordenar, expirar o correlacionar eventos.

Cada productor mantendrá y registrará, junto con la observación o mediante un snapshot temporal referenciado e inmutable:

- offset estimado de su reloj respecto de la referencia UTC utilizada;
- incertidumbre no negativa de esa estimación;
- drift estimado del reloj;
- fuente o método de sincronización;
- instante en que se evaluó la calidad temporal.

Los contratos definirán unidades y convención de signo sin depender de la zona horaria civil. La ausencia de una estimación válida se representará explícitamente y reducirá la confianza de toda correlación que la utilice.

Se distinguirán, cuando correspondan, el instante declarado por el productor, el instante de recepción por el servidor y el instante de persistencia. El retraso de transporte no se reinterpretará como tiempo de ocurrencia.

Las duraciones locales se medirán con un reloj monotónico cuando la plataforma lo permita. Los saltos del reloj de pared no podrán producir duraciones negativas ni extender límites de tráfico. Los vencimientos de tareas, leases y reservas serán evaluados por el servidor con su propia referencia temporal; el reloj del agente no podrá ampliar una autorización.

La correlación entre planos usará identificadores comunes de ejecución, tarea, reserva y artefacto, además del tiempo. Las ventanas temporales incorporarán la incertidumbre de las fuentes. Si la incertidumbre o el drift impiden establecer el orden requerido, el sistema marcará la relación como aproximada o no concluyente y no afirmará causalidad precisa.

## Consequences

- Los eventos y muestras requerirán metadatos temporales adicionales o una referencia inequívoca a un snapshot de reloj.
- La correlación podrá degradarse de forma explícita en lugar de producir una precisión ficticia.
- Los agentes deberán conservar mediciones monotónicas para duración y capturar periódicamente la calidad de su reloj.
- Las consultas y reportes deberán distinguir tiempo de ocurrencia, recepción y persistencia.
- Los contract tests incluirán drift, offset desconocido, reloj corregido, carga retrasada y expiración con reloj del agente divergente.

## Alternatives considered

- Confiar únicamente en el timestamp del agente. Se descartó porque los relojes pueden estar desincronizados o corregirse durante la prueba.
- Usar sólo el tiempo de recepción del servidor. Se descartó porque la cola y la conectividad diferida destruyen la secuencia real de observación.
- Asumir que NTP garantiza sincronización suficiente. Se descartó porque no todas las plataformas exponen igual calidad ni mantienen sincronización continua.
- Exigir sincronización de alta precisión para toda ejecución. Se descartó para el MVP porque no es viable en todos los endpoints y ocultaría capabilities legítimas con menor precisión.

## Deferred decisions

- El protocolo concreto de sincronización y si ciertos laboratorios usarán NTP, PTP, GPS u otra referencia.
- Los umbrales de incertidumbre aceptables para cada tipo de análisis.
- La forma exacta de serializar snapshots temporales en OpenAPI y JSON Schema.
- Los algoritmos de alineación avanzada entre captura 802.11, endpoint e infraestructura.

## References

- [AGENTS.md](../../../AGENTS.md)
- [Prompt 01 - Arquitectura, ADRs y modelo de amenazas](../../../prompts/01_architecture_and_adrs.md)
- [ADR-0002: Domain and plane boundaries](0002-domain-and-plane-boundaries.md)
- [Runtime flows](../runtime-flows.md)
