# Fase 04: contratos, capabilities y enrolamiento

La Fase 04 publica el protocolo inicial de agentes. La autoridad normativa se
divide sin duplicaciones:

- `shared/contracts/schemas/`: payloads JSON Schema Draft 2020-12.
- `shared/contracts/openapi/`: operaciones OpenAPI 3.1.
- `shared/contracts/examples/`: golden fixtures indexados por un manifest.
- `shared/contracts/catalog/`: IDs, compatibilidad e integridad de la release.

FastAPI sirve el OpenAPI canónico bundled. Los endpoints `/demo` y los stubs
internos de tareas/resultados no forman parte de la API normativa.

| Nivel | Versión |
|---|---|
| Producto | `0.1.0` |
| API HTTP | `v1` |
| JSON Schema | `1.0.0` |
| Agent Protocol | `1.0.0` |
| Capability catalog | `1.0.0` |
| Capability Manifest | `1.0.0` |

Referencias:

- [Contratos, fixtures y consumidores](contracts.md)
- [Protocolo, compatibilidad y presence](protocol.md)
- [Capabilities](capabilities.md)
- [Enrolamiento, credenciales e idempotencia](enrollment-and-credentials.md)
- [Runbook, seguridad, migración y rollback](operations.md)
