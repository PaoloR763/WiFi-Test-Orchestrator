# Prompt 22 - SDK de plugins, versionado y migraciones

## Objetivo

Convertir la extensibilidad en un contrato formal para futuras funciones sin romper instalaciones existentes.

## Prerrequisitos

- Arquitectura y varios plugins existentes.

## Alcance

- Plugin manifests.
- Lifecycle.
- Compatibility.
- Schema migrations.
- Feature flags.
- Deprecation.
- Examples.

## Requisitos de implementación

- PluginManifest con id, semantic version, API version, capabilities, config schema, result schema, platforms, permissions, resources y signatures.
- Discovery controlado; no cargar código arbitrario descargado.
- Version negotiation entre servidor/agente/plugin.
- Configuraciones validadas y secrets references.
- Result schema versionado.
- Migraciones de DB y de configuración con rollback.
- Feature flags y staged rollout.
- Deprecation policy con warning, sunset y compatibility window.
- SDK examples para TestPlugin, TrafficGenerator, Adapter y ReportRenderer.
- Conformance test suite para terceros internos.
- Changelog y release notes obligatorios.
- No permitir plugins sin firma/allowlist en producción.

## Tests obligatorios

- Plugin incompatible.
- Migration upgrade/downgrade.
- Old agent/new server.
- New agent/old server.
- Feature flag rollback.
- Conformance tests.
- Signature failure.

## Documentación obligatoria

- Guía de extensión paso a paso.
- Política semver.
- Matriz de compatibilidad.
- Plantillas de ADR/migration/changelog.

## Criterios de aceptación

- Se añade un plugin de ejemplo sin tocar el core.
- Compatibilidad se valida automáticamente.
- Migraciones son reversibles o documentan no-retorno.
- Deprecaciones son visibles.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
