# Prompt 18 - Frontend, dashboards y flujos operativos

## Objetivo

Construir una interfaz web que permita operar el producto sin depender de Swagger o acceso directo a base de datos.

## Prerrequisitos

- Backend y campañas disponibles.

## Alcance

- Login.
- Inventory.
- Capabilities.
- Campaign builder.
- Live progress.
- Results.
- Telemetry.
- Artifacts.
- Admin.

## Requisitos de implementación

- React/TypeScript con API client generado o tipado.
- Pantallas responsive y accesibles.
- Inventario con estado, last seen, plataforma, versión y capabilities.
- Detalle con availability/source por campo.
- Campaign builder con preflight y advertencias mobile.
- Progreso por eventos.
- Gráficos de throughput, latency-under-load, RSSI, PHY rate y loss.
- Comparador con filtros por método/plataforma/firmware.
- Descarga de artefactos y reportes.
- RBAC en UI y backend.
- Timezone configurable.
- Estados vacíos/errores claros.
- No ocultar SKIPPED/BLOCKED.

## Tests obligatorios

- Component tests.
- API contract tests.
- Playwright E2E.
- Accessibility checks.
- Large dataset pagination.
- Reconnect live updates.

## Documentación obligatoria

- Guía de usuario.
- Mapa de pantallas.
- Convenciones de gráficos.
- Troubleshooting UI.

## Criterios de aceptación

- Operador completa flujo end-to-end.
- Los gráficos explican método.
- RBAC efectivo.
- Errores y limitaciones visibles.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
