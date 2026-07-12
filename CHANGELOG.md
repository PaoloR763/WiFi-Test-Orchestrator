# Changelog

Todos los cambios relevantes de WiFi Test Orchestrator se documentarán en este
archivo.

El formato se inspira en Keep a Changelog y el producto utilizará Semantic
Versioning cuando existan releases publicadas.

## Unreleased

### Added

- Baseline arquitectónico para el producto inicial `0.1.0`.
- Separación de control, data, telemetry, artifact e integration planes.
- ADRs para stack, contratos, capabilities, delivery, almacenamiento,
  lifecycle móvil, tráfico, tiempo, captura, plugins y deployment.
- Diagramas Mermaid de contexto, componentes, topologías y flujos.
- Threat model inicial y matriz multidimensional de capabilities.
- Reglas conceptuales de métricas, límites, reservas y compatibilidad.
- Monorepo ejecutable de Fase 02 con backend, frontend, worker, reverse proxy,
  PostgreSQL, Redis, artifact store filesystem y agente simulado outbound-only.
- Health/readiness, logs JSON, correlation IDs, scripts equivalentes, tests y
  CI Linux basada en contenedores.

### Changed

- `docs/architecture/` pasa a ser la ubicación canónica de arquitectura.
- README actualizado para reflejar versiones, prioridades y restricciones.
- Alineado el contexto normativo maestro con los ADRs aceptados: `reason` es el
  único nombre conceptual para explicar indisponibilidad, condicionamiento,
  degradación o decisiones de ejecución; `value: null` nunca significa cero.
- Separadas las dimensiones conceptuales del capability manifest en
  `technical_support`, `implementation_status`, `permission_requirement`,
  `user_interaction`, `background_execution`, `provider` y `limitations`, sin
  cerrar vocabularios ni JSON Schema antes de la Fase 04.
- Alineados los ejemplos de capability IDs con el baseline conceptual aprobado.
- Alineadas las instrucciones específicas de `prompts/` con el contexto
  normativo raíz y los ADRs aceptados.
- Documentado el flujo local Windows/WSL2 y Linux, troubleshooting, rollback y
  mapa del monorepo.

### Security

- Documentados controles para enrolamiento, credenciales, leases,
  idempotencia, tráfico autorizado, captura, plugins y cambios de
  infraestructura.
- PostgreSQL, Redis y servicios internos no publican puertos; el reverse proxy
  no privilegiado es el único ingreso normal del entorno local.

## Release status

No se publicó todavía una versión funcional ni se creó un tag de release.
