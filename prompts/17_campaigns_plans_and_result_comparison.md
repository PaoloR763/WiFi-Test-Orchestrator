# Prompt 17 - Casos, suites, planes, campañas y comparación

## Objetivo

Implementar la capa de gestión de pruebas con versionado, snapshots, scheduling y comparación honesta.

## Prerrequisitos

- Prompts 10-16 completos.

## Alcance

- TestCase.
- Suite.
- Plan.
- Campaign.
- Targets.
- Thresholds.
- Baseline.
- Comparison.

## Requisitos de implementación

- Versionar definiciones; published versions inmutables.
- Snapshot de plugins, providers, manifests, thresholds y parámetros al lanzar.
- Selección por dispositivo, grupo, tag, plataforma o capability.
- Preflight que muestre ejecutable/skipped/blocked.
- Repeticiones, serial/paralelo, max concurrency y ventanas.
- Pausa/reanudación/cancelación.
- Rerun selectivo.
- Baselines por modelo/firmware/plataforma.
- Comparison engine con reglas de equivalencia de método.
- Estadística básica con sample size, dispersion y outliers documentados.
- No cambiar PASS/FAIL histórico al editar thresholds.

## Tests obligatorios

- Version publish.
- Snapshot.
- Campaña heterogénea.
- Rerun.
- Comparison incompatible.
- Scheduling.
- Concurrency.
- Historical immutability.

## Documentación obligatoria

- Modelo funcional.
- Guía de diseño de campañas.
- Reglas de comparación.
- Ejemplos de ATP.

## Criterios de aceptación

- Campañas reproducibles.
- Resultados históricos inmutables.
- Preflight evita fallas por incompatibilidad.
- Comparaciones muestran método y tamaño de muestra.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
