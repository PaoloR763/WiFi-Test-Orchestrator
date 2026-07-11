# Prompt 04 - Contratos, capabilities y enrolamiento de agentes

## Objetivo

Estabilizar los contratos compartidos y el proceso seguro de enrolamiento, presencia, rotación y revocación.

## Prerrequisitos

- Prompt 03 completo.
- ADRs de protocolo aprobados.

## Alcance

- OpenAPI.
- JSON Schemas.
- Golden fixtures.
- Enrolamiento.
- Heartbeat/presence.
- Capability manifests.

## Requisitos de implementación

- Definir schemas para AgentRegistration, AgentCredential, CapabilityManifest, TaskEnvelope, ProgressEvent, TestResult y ArtifactManifest.
- Incluir schema_version e idempotency_key.
- Tokens de enrolamiento de uso limitado y expiración.
- Emitir identidad individual y credencial rotatable.
- Soportar revocación inmediata.
- Heartbeat desktop; presence/fetch mobile.
- Capability manifest con supported/conditional/permission_required/user_interaction_required.
- Crear generadores/validadores de modelos para Python, TypeScript, Kotlin y Swift cuando sea viable.
- Mantener ejemplos en `shared/contracts/examples`.

## Tests obligatorios

- Contract tests en cuatro lenguajes o validadores equivalentes.
- Replay/idempotency.
- Token expirado/consumido.
- Clock skew.
- Revocación.
- Manifests incompatibles.

## Documentación obligatoria

- Referencia del protocolo.
- Diagramas de secuencia.
- Catálogo de capabilities.
- Política de versionado.

## Criterios de aceptación

- Un agente simulado se enrola y rota credenciales.
- Un agente revocado no obtiene tareas ni sube resultados.
- Los fixtures son válidos en todos los consumidores.
- Cambios incompatibles son detectados.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
