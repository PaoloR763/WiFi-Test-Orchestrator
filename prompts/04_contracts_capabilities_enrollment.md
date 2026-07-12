# Prompt 04 - Contratos, capabilities y enrolamiento de agentes

## Objetivo

Estabilizar los contratos compartidos y el proceso seguro de enrolamiento, presencia, rotación y revocación.

## Prerrequisitos

- Prompt 03 completo.
- ADRs de protocolo aprobados.

## Alcance

- OpenAPI.
- JSON Schemas.
- Fuente contractual canónica y golden fixtures normativos.
- Enrolamiento.
- Heartbeat/presence.
- Capability manifests.

## Requisitos de implementación

- Usar `shared/contracts/` como única fuente normativa para OpenAPI, JSON
  Schemas y demás contratos compartidos. Todo mensaje o documento contractual
  versionado de nivel superior debe incluir `schema_version`.
- Definir schemas para AgentRegistration, AgentCredential, CapabilityManifest,
  TaskEnvelope, ProgressEvent, TestResult y ArtifactManifest.
- Exigir `idempotency_key` sólo en operaciones, comandos, requests o eventos
  que puedan reintentarse, duplicarse o reproducirse. No agregarla
  indiscriminadamente a credenciales, manifests ni estructuras donde no tenga
  semántica. Definir en esta fase su semántica, alcance, retención y reglas de
  unicidad.
- Tokens de enrolamiento de uso limitado y expiración.
- Emitir identidad individual y credencial rotatable. Una credencial secreta
  puede entregarse una sola vez durante el enrolamiento o la rotación; después
  sólo se almacena una representación segura y nunca el secreto en texto plano.
- Redactar credenciales y tokens en logs, errores y auditoría.
- Soportar revocación inmediata.
- Heartbeat desktop; presence/fetch mobile.
- Modelar cada capability del CapabilityManifest mediante dimensiones
  conceptuales separadas: `technical_support`, `implementation_status`,
  `permission_requirement`, `user_interaction`, `background_execution`,
  `provider` y `limitations`.
- No crear un campo único `support`, no colapsar las siete dimensiones y no
  mezclar la identidad de una capability con el provider que la implementa.
  `reason` será el único campo conceptual explicativo para indisponibilidad,
  condicionamiento, degradación o decisiones de ejecución; no definir
  `availability_reason`.
- Definir en esta fase vocabularios versionados, cardinalidades y JSON Schemas
  para las siete dimensiones. Los vocabularios deben permitir evolución
  compatible sin perder la separación multidimensional.
- Adoptar como capability IDs canónicos:
  - `wifi.connection.read`
  - `wifi.scan`
  - `wifi.rssi.read`
  - `network.icmp.ping`
  - `network.tcp.probe`
  - `network.http.probe`
  - `traffic.tcp.throughput`
  - `traffic.udp.throughput`
  - `traffic.http.download`
  - `traffic.http.upload`
  - `traffic.latency_under_load`
  - `capture.ip`
  - `capture.ieee80211.monitor`
  - `traffic.pcap.replay`
  - `execution.background.continuous`
- Tratar iperf3 exclusivamente como provider intercambiable de throughput, no
  como capability ni como parte de un capability ID.
- Crear generadores o validadores de modelos para Python, TypeScript, Kotlin y
  Swift a partir de la única fuente contractual canónica. Cuando la generación
  automática no sea viable o confiable, se permiten validadores o modelos
  manuales equivalentes respaldados por contract tests.
- Mantener en `shared/contracts/examples/` los golden fixtures normativos y
  validados por los cuatro consumidores. No declarar soporte completo de un
  lenguaje cuando sólo exista una validación sintáctica superficial.
- Tratar `prompts/examples/` como ejemplos históricos no normativos: no son
  fuente contractual y no deben convertirse automáticamente en fixtures.
- No incluir secretos reales de AgentCredential en golden fixtures. Usar sólo
  valores sintéticos no utilizables y verificar que tampoco se filtren en logs,
  errores ni auditoría.

## Tests obligatorios

- Contract tests en cuatro lenguajes o validadores equivalentes.
- Los cuatro consumidores validan los mismos golden fixtures normativos.
- Replay/idempotency, incluidas semántica, alcance, retención y unicidad de las
  claves.
- Token expirado/consumido.
- Clock skew.
- Revocación.
- Manifests incompatibles.
- Entrega única y almacenamiento seguro de credenciales durante enrolamiento y
  rotación, con redacción en logs, errores y auditoría.

## Documentación obligatoria

- Referencia del protocolo.
- Diagramas de secuencia.
- Catálogo de capabilities.
- Política de versionado.

## Criterios de aceptación

- Un agente simulado se enrola y rota credenciales.
- Un agente revocado no obtiene tareas ni sube resultados.
- Los fixtures son válidos en todos los consumidores.
- Los golden fixtures no contienen secretos utilizables.
- Cambios incompatibles son detectados.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
