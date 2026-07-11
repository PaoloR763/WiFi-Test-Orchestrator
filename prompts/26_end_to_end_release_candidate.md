# Prompt 26 - Validación end-to-end y release candidate

## Objetivo

Auditar la solución completa, ejecutar escenarios heterogéneos y producir una release candidate reproducible.

## Prerrequisitos

- Prompts 01-25 completados.

## Alcance

- E2E server.
- Four agent platforms.
- Traffic providers.
- Campaigns.
- Artifacts.
- Security.
- Backup/restore.
- Release.

## Requisitos de implementación

- Levantar servidor en Windows 11 + WSL2 desde checkout limpio.
- Enrolar Windows, Linux, Android y iOS reales o la mejor combinación real/simulada documentada.
- Validar manifests distintos.
- Ejecutar latency, DNS, HTTP, iperf3 desktop, native mobile y latency-under-load.
- Ejecutar campaña heterogénea con PASS, FAIL, SKIPPED y BLOCKED.
- Forzar servidor offline, agente restart, app background y upload interrumpido.
- Verificar no duplicación.
- Generar reportes y comparar baseline.
- Validar revocación, RBAC y auditoría.
- Probar backup/restore y upgrade N-1.
- Ejecutar security scans y SBOM.
- Revisar documentación y known issues.
- Etiquetar release candidate solo si gates pasan.

## Tests obligatorios

- E2E Playwright/API.
- Desktop integration.
- Android instrumented.
- iOS XCTest/device.
- Chaos.
- Load.
- Security.
- Restore.
- Upgrade.

## Documentación obligatoria

- Release notes.
- Known issues.
- Evidence bundle.
- Compatibility matrix.
- Operations handoff.
- Go/no-go checklist.

## Criterios de aceptación

- Instalación reproducible.
- Escenario E2E completo.
- No hay secretos ni vulnerabilidades críticas conocidas.
- Rollback y restore probados.
- Limitaciones están visibles.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
