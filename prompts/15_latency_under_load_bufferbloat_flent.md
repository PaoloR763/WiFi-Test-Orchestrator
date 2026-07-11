# Prompt 15 - Latencia bajo carga, bufferbloat y Flent

## Objetivo

Implementar pruebas compuestas que midan latencia antes, durante y después de una carga controlada, con una integración opcional de Flent.

## Prerrequisitos

- Prompts 11-14 completos.

## Alcance

- Composite test runner.
- Independent probes.
- Load phases.
- Bufferbloat metrics.
- Flent adapter opcional.
- RRUL-like profile.

## Requisitos de implementación

- Ejecutar baseline, warmup, load, cooldown y recovery.
- Usar probe independiente simultáneo al TrafficGenerator.
- Soportar ICMP/TCP/HTTP latency con etiqueta de método.
- Calcular median, p95, p99, jitter, loss y latency increase respecto de baseline.
- Definir severidad configurable, no universal.
- Crear perfiles download-load, upload-load, bidirectional-load y multi-stream.
- Integrar Flent en Linux si está instalado; importar JSON y metadata.
- No hacer Flent dependencia del MVP ni ejecutar netperf remoto sin allowlist.
- Sincronizar timestamps monotónicos y conservar raw series.
- Visualizar series y fases.
- Distinguir bufferbloat inferido de causas Wi-Fi/radio no observadas.

## Tests obligatorios

- Probe falla durante carga.
- Clock alignment.
- Baseline inestable.
- High loss.
- Cancelación.
- Flent ausente.
- Golden series.
- Regression test de cálculos.

## Documentación obligatoria

- Definición de métricas.
- Perfiles y thresholds.
- Guía Flent.
- Interpretación y límites diagnósticos.

## Criterios de aceptación

- La prueba muestra latencia en reposo y bajo carga.
- Puede ejecutarse sin Flent.
- Los cálculos son reproducibles.
- El reporte evita conclusiones no sustentadas.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
