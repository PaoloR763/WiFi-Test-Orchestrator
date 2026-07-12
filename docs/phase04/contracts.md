# Contratos, OpenAPI y consumidores

## Fuente de verdad y drift

Cada payload tiene una sola definición JSON Schema. OpenAPI referencia esos
archivos y `scripts/build_openapi.py` crea
`backend/src/wto_backend/contract_data/openapi-bundled.json`, preservando `$defs`
y referencias entre schemas. FastAPI sirve ese archivo; no genera una segunda
especificación pública.

`scripts/check_openapi_drift.py` valida OpenAPI 3.1 y compara rutas, métodos,
status principal, modelos Pydantic, security schemes, headers de agente y el
ErrorEnvelope común. `scripts/check_contract_compatibility.py` detecta reglas
incompatibles y verifica hashes SHA-256 de la release `1.0.0`. Los DTOs tienen
`extra="forbid"`; los tests prueban DTO y schema sobre los mismos payloads.

## Clasificación

El inventario normativo de Fase 04 contiene exactamente 14 JSON Schemas. El
número 15 corresponde al catálogo de capability IDs, no al inventario de
schemas. No existe un decimoquinto contrato exigido por Prompt 04, AGENTS.md,
los ADRs, OpenAPI ni el manifest de fixtures.

| Archivo canónico | Clase contractual |
|---|---|
| `agent-credential.schema.json` | secreto de entrega única y metadata |
| `agent-registration-request.schema.json` | request de enrolamiento |
| `agent-registration-response.schema.json` | response de enrolamiento |
| `artifact-manifest.schema.json` | metadata; nunca bytes de artifact |
| `capability-manifest.schema.json` | documento versionado multidimensional |
| `common.schema.json` | definiciones compartidas de IDs, versiones y tiempo |
| `desktop-heartbeat.schema.json` | evento de presence desktop |
| `error-envelope.schema.json` | error común de API |
| `metric.schema.json` | envelope tipado; `null` no equivale a cero |
| `mobile-presence.schema.json` | evento de presence mobile |
| `progress-event.schema.json` | evento reintentable de progreso |
| `reason.schema.json` | explicación cerrada reutilizable |
| `task-envelope.schema.json` | comando/envelope mínimo provisional |
| `test-result.schema.json` | documento de resultado provisional |

Todos son cerrados, limitados, usan UTC y UUID, y llevan `schema_version` en el
nivel superior. Extensiones futuras requieren schema/version, ownership y
límite; no se aceptan objetos JSON arbitrarios.

## Golden fixtures y consumidores

`examples/manifest.json` enumera schema, validez y keyword de error. Cubre
enrolamiento, credentials sintéticas, desktop/mobile, envelopes futuros,
versiones, idempotencia, campos/enums desconocidos, providers, límites y `null`
frente a cero. `prompts/examples/` no se consume.

- Python 3.12: jsonschema 4.25.1 Draft 2020-12 y Pydantic 2.11.7.
- TypeScript: Node 22.16, TypeScript 5.8.3, Ajv 8.20.0 y ajv-formats 3.0.1.
- Kotlin: JDK 21, Kotlin 2.1.21 y Gradle 8.14.2, con wrapper, dependency
  locking, checksums y modelos semánticos estrictos.
- Swift: Swift 6.1.2/Linux y validación Codable/semántica estricta.

Swift y Kotlin compilan y ejecutan todo el manifest, pero no se presentan como
validadores generales de Draft 2020-12. En particular, `swift test` compila el
package, lee el mismo `shared/contracts/examples/manifest.json` y aplica decode
Codable más validación semántica manual a sus 25 fixtures: acepta los 12 válidos
y rechaza los 13 inválidos. Ajv y Python sí validan el draft. Las imágenes OCI
están fijadas por digest y CI ejecuta consumidores en paralelo.

El wrapper Kotlin se ejecuta desde el repositorio, no desde un Gradle global.
Su único JAR exceptuado de la regla general de ignore tiene SHA-256
`7d3a4ac4de1c32b59bc6a4eb8ecb8e612ccd0cf1ae1e99f66902da64df296172`.
`gradle-wrapper.properties` conserva además `distributionSha256Sum` para la
distribución Gradle 8.14.2. El guardrail del repositorio valida presencia, hash,
estado no ignorado e inclusión por Git.

Cambios aditivos opcionales admiten minor; correcciones sin semántica admiten
patch. Required agregado, campo eliminado, tipo/pattern/límite restringido,
enum reducido, discriminator, capability ID, dimensión o semántica de null
requieren major, migración y ventana de coexistencia.
