# Prompt 23 - Seguridad, observabilidad y CI/CD

## Objetivo

Endurecer el sistema, instrumentarlo y crear pipelines reproducibles para todas las plataformas.

## Prerrequisitos

- Funcionalidad principal integrada.

## Alcance

- Security controls.
- Metrics/logs/traces.
- CI matrices.
- SAST/SCA.
- SBOM.
- Load/chaos.
- Release gates.

## Requisitos de implementación

- Threat model actualizado.
- TLS/mTLS o credenciales robustas según ADR.
- Rate limiting y abuse controls.
- Secret scanning, dependency scanning, container scanning y SAST.
- SBOM por release y firmas de artefactos.
- Prometheus metrics y OpenTelemetry traces donde aporte valor.
- Structured logs con redacción y correlation IDs.
- Dashboards operativos y alertas.
- CI backend/frontend/desktop/Android; iOS en runner macOS.
- Contract tests cross-language.
- Load tests de ingestión, task leasing y artifact upload.
- Chaos tests controlados.
- Backups, restore tests y disaster recovery objectives.
- No exponer Docker daemon sin TLS.

## Tests obligatorios

- Security regression.
- Load targets.
- Agent storm.
- Redis/Postgres restart.
- Artifact store outage.
- Backup restore.
- CI clean checkout.

## Documentación obligatoria

- Security baseline.
- Runbooks de alertas.
- SLOs/SLIs.
- Pipeline y release gate.
- Backup/DR.

## Criterios de aceptación

- Builds reproducibles.
- Vulnerabilidades críticas bloquean release.
- Métricas permiten diagnosticar.
- Restore probado.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
