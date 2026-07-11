# Prompt 10 - Orquestación, leases y entrega mobile

## Objetivo

Implementar el ciclo de vida de tareas para desktop y mobile con idempotencia, expiración, recuperación y estados explícitos.

## Prerrequisitos

- Prompts 04-09 disponibles.

## Alcance

- Queueing.
- Leases.
- Claims.
- Progress.
- Cancellation.
- Mobile hints.
- Preflight de capabilities.
- Concurrency.

## Requisitos de implementación

- Estados: QUEUED, OFFERED, CLAIMED, RUNNING, WAITING_FOR_FOREGROUND, WAITING_FOR_USER, COMPLETED, FAILED, CANCELED, EXPIRED, SKIPPED, BLOCKED.
- Lease con renovación y fencing token.
- No reasignar efecto activo sin expiración segura.
- Push Android/iOS solo como señal.
- Preflight de capabilities, permisos, batería, conectividad y foreground.
- Límites de concurrencia global, por agente, test server y laboratorio.
- Scheduling con not_before/expires_at.
- Cancelación cooperativa y cleanup.
- Eventos inmutables y proyección de estado.
- WebSocket/SSE para frontend sin convertirlo en canal de control del agente.

## Tests obligatorios

- Dos agentes reclaman la misma tarea.
- Lease expira.
- Progress fuera de orden.
- Resultado duplicado.
- Push no entregado.
- App cerrada.
- Cancelación durante upload.
- Chaos tests.

## Documentación obligatoria

- Máquina de estados.
- Runbook de tareas atascadas.
- Semántica de mobile delivery.
- Métricas operativas.

## Criterios de aceptación

- No hay doble ejecución efectiva.
- Estados explican por qué no se ejecutó.
- Desktop recupera automáticamente.
- Mobile no depende de ejecución inmediata.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
