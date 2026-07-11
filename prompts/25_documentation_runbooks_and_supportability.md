# Prompt 25 - Documentación, runbooks y soporte futuro

## Objetivo

Completar documentación operativa y de desarrollo para que nuevas funciones puedan incorporarse sin depender del equipo original.

## Prerrequisitos

- Todas las funciones principales disponibles.

## Alcance

- Developer docs.
- Operator docs.
- API reference.
- Runbooks.
- Troubleshooting.
- Extension tutorials.
- Architecture index.

## Requisitos de implementación

- Crear portal/docs navegable con MkDocs o equivalente.
- Documentar instalación, configuración, seguridad, backup, restore, upgrade y rollback.
- Referencia OpenAPI y schemas.
- Guías para agregar TestPlugin, TrafficGenerator, Adapter, CaptureProvider y ReportRenderer.
- Ejemplos completos y golden fixtures.
- Runbooks: agente offline, task stuck, server busy, high ingest lag, artifact failure, clock skew, mobile background, iperf server saturated.
- Troubleshooting por Windows/Linux/Android/iOS.
- Decision log y changelog.
- Matriz de compatibilidad y deprecaciones.
- Diagramas actualizados automáticamente o validados.
- Documentar límites conocidos y próximos pasos.
- Agregar templates para feature proposal, ADR, migration plan y test plan.

## Tests obligatorios

- Link checker.
- Docs build.
- Code examples tested.
- Fresh-user walkthrough.
- Runbook tabletop exercise.

## Documentación obligatoria

- Todo el alcance de esta fase es documentación.
- Agregar índice y ownership por sección.

## Criterios de aceptación

- Un desarrollador nuevo puede añadir un plugin de ejemplo.
- Un operador puede diagnosticar fallas comunes.
- Los ejemplos compilan/pasan tests.
- No hay links rotos.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
