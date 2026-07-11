# Prompt 16 - Telemetría, eventos Wi-Fi y sincronización temporal

## Objetivo

Implementar ingestión escalable, availability maps, detección de eventos y una estrategia explícita de tiempo.

## Prerrequisitos

- Agentes y contratos disponibles.

## Alcance

- Samples.
- Batches.
- Events.
- Clock metadata.
- Retention.
- Downsampling.
- Exports.

## Requisitos de implementación

- Batches idempotentes y compresión.
- Conservar collected_at, received_at, monotonic offset, clock quality y timezone metadata.
- No confiar ciegamente en reloj del agente; detectar skew y jumps.
- Normalizar Wi-Fi fields con source/availability/confidence.
- Eventos: association, disconnect, BSSID change, channel/frequency change, IP/path change, agent restart y telemetry gap.
- Reglas de deduplicación y debounce.
- Retención configurable, particionamiento y downsampling.
- Export CSV/JSON.
- Métricas de ingest lag, rejected samples y gaps.
- Preparar integración futura con TimescaleDB sin hacerla obligatoria.

## Tests obligatorios

- Batch duplicado.
- Out-of-order.
- Clock jump.
- Offline backlog.
- Event debounce.
- Retention.
- Load tests.

## Documentación obligatoria

- Diccionario de datos.
- Semántica temporal.
- Política de retención.
- Guía de queries.

## Criterios de aceptación

- No duplica muestras.
- Eventos son explicables.
- Series preservan calidad temporal.
- Dashboards funcionan con downsampling.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
