# ADR-0008: Lifecycle móvil y push sólo como aviso

## Status

Accepted

## Context

Android e iOS no permiten asumir un daemon permanente ni ejecución inmediata en background. El sistema operativo puede demorar, suspender o finalizar una aplicación; los permisos pueden cambiar y algunas operaciones requieren foreground visible o interacción del usuario. FCM y APNs tampoco garantizan entrega inmediata, orden ni entrega única.

Tratar una notificación push como una orden autoritativa produciría tareas perdidas, duplicadas o ejecutadas con parámetros obsoletos. También expondría información operativa y mezclaría identidad, scheduling y transporte de terceros con el contrato servidor-agente.

## Decision

- La recuperación de tareas será siempre por HTTPS outbound-only iniciado y autenticado por el agente. El servidor nunca dependerá de una conexión entrante al dispositivo.
- FCM y APNs serán avisos best-effort para sugerir que el agente consulte al servidor. El payload no contendrá comandos ejecutables, parámetros de prueba, reservas de tráfico, secretos ni credenciales; como máximo incluirá un hint opaco no autoritativo.
- Recibir un push no asigna una tarea ni adquiere un lease. El agente recuperará por HTTPS el envelope versionado, validará expiración, idempotencia, capabilities, permisos y restricciones de lifecycle, y sólo entonces solicitará o confirmará el lease correspondiente.
- La corrección del sistema no dependerá del push. Polling permitido por la plataforma, reanudación de la aplicación y acciones explícitas del usuario deberán converger sobre la misma cola persistente.
- Notificaciones duplicadas, fuera de orden o ausentes no modificarán la semántica. La identidad de tarea y la `idempotency_key`, no el identificador de notificación, gobernarán la deduplicación.
- En Android, las pruebas activas que requieran continuidad usarán Foreground Service con indicación visible cuando la versión y política del sistema lo permitan. WorkManager se reservará para trabajo diferible y recuperable; no se usará para prometer inicio exacto.
- En iOS/iPadOS, el agente será foreground-first. BackgroundTasks y URLSession background se usarán sólo para trabajos compatibles y en ventanas concedidas por el sistema. APNs no se interpretará como garantía de ejecución ni como bypass de estas restricciones.
- Antes de adquirir un lease, el agente evaluará si dispone de una ventana de ejecución suficiente y de los permisos necesarios. Si no puede ejecutar, informará `SKIPPED` o `BLOCKED` con una razón estructurada, sin simular soporte.
- Si el sistema suspende al agente durante una ejecución, los checkpoints locales, la renovación del lease y la idempotencia permitirán reanudar, reintentar o cerrar la ejecución de forma explicable. No se prometerá continuidad donde la plataforma no la ofrece.
- El Capability Manifest publicará por separado `technical_support`, `implementation_status`, `permission_requirement`, `user_interaction`, `background_execution`, `provider` y `limitations` para cada capability.
- Los tokens de FCM/APNs se tratarán como metadatos revocables de delivery, separados de la identidad y de las credenciales del agente, protegidos en almacenamiento y excluidos de logs.

## Consequences

- Android e iOS comparten el contrato de recuperación HTTPS sin fingir paridad de ejecución.
- La pérdida o demora de un push afecta latencia de inicio, pero no pierde la tarea ni concede autoridad incorrecta.
- Algunas tareas quedarán `SKIPPED`, `BLOCKED` o esperarán interacción; la UI deberá explicar el motivo.
- Las campañas deben contemplar ventanas de foreground, batería, conectividad y permisos al estimar capacidad.
- Se necesitan métricas separadas para delivery del aviso, recuperación HTTPS, adquisición de lease e inicio efectivo.
- El comportamiento background variará entre versiones y políticas del sistema operativo y deberá mantenerse en la matriz de capabilities.

## Alternatives considered

- **Incluir la tarea completa en FCM/APNs:** se descarta por seguridad, tamaño, obsolescencia y falta de garantías de entrega.
- **Tratar silent push como disparador garantizado:** se descarta porque ambas plataformas pueden retrasarlo o suprimirlo.
- **Mantener un socket permanente en mobile:** se descarta porque no es confiable bajo suspensión y aumenta consumo y complejidad.
- **Imponer paridad con los servicios desktop:** se descarta porque contradice los lifecycle y permisos reales de Android e iOS.
- **Omitir push y exigir foreground manual para todo:** se descarta como única estrategia porque reduce innecesariamente la oportunidad de recuperación, aunque seguirá siendo un fallback válido.

## Deferred decisions

- Cadencias de polling y políticas de backoff por plataforma y estado de energía.
- TTL, collapse keys y contenido exacto del hint de FCM/APNs.
- Flujos UX para solicitar permisos, foreground e interacción del usuario.
- Capabilities concretas elegibles para cada mecanismo background según versión de Android o iOS.
- Proveedor y configuración operativa de los servicios de push.

## References

- [AGENTS.md](../../../AGENTS.md), secciones 2, 3, 7 y 8.
- [Prompt 01 - Arquitectura, ADRs y modelo de amenazas](../../../prompts/01_architecture_and_adrs.md).
- [ADR-0006: Cola de ejecución persistente y abstracción de workers](0006-persistent-execution-queue-and-worker-abstraction.md).
- [ADR-0009: Enrolamiento, identidad y rotación de credenciales](0009-agent-enrollment-identity-and-credential-rotation.md).
