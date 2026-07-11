# Prompt 24 - Packaging, distribución y actualizaciones

## Objetivo

Empaquetar servidor y agentes, firmar entregables y diseñar upgrades/rollback por plataforma.

## Prerrequisitos

- Prompt 23 completo.

## Alcance

- Server bundle.
- Windows installer.
- Linux packages.
- Android builds.
- iOS distribution.
- Update service.
- Rollback.

## Requisitos de implementación

- Servidor: Compose versionado y opción Helm futura.
- Windows: MSI/MSIX o instalador aprobado, servicio, code signing y upgrade in-place.
- Linux: DEB y diseño RPM, systemd hardening.
- Android: APK/AAB firmado, canales interno/MDM/Play según estrategia.
- iOS: development/TestFlight/MDM; no prometer instalación desde Windows.
- Update manifest firmado con version, hash, compatibility y rollout ring.
- Desktop auto-update con descarga verificada y rollback.
- Mobile updates mediante canales de plataforma.
- DB migrations coordinadas con compatibility window.
- Canary/staged rollout y kill switch.
- Inventario de versiones y compliance.
- Uninstall y data retention policy.

## Tests obligatorios

- Upgrade N-1 a N.
- Rollback.
- Interrupted install.
- Invalid signature.
- Old agent compatibility.
- Canary abort.
- Fresh install.

## Documentación obligatoria

- Guías de instalación por plataforma.
- Release checklist.
- Update protocol.
- Rollback runbook.
- Matriz de soporte.

## Criterios de aceptación

- Instalaciones reproducibles.
- Firmas verificadas.
- Rollback documentado.
- Servidor tolera versiones soportadas de agentes.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
