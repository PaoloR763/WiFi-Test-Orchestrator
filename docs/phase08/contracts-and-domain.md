# Fase 08 — Contratos wire Android

## Alcance implementado en C02A

C02A incorpora únicamente modelos wire Kotlin/JVM para el enrolamiento público
del agente Android. No constituye un flujo de enrolamiento ejecutable ni una
aplicación Android funcional.

La fuente normativa permanece en:

- `shared/contracts/openapi/openapi.json`;
- `shared/contracts/schemas/common.schema.json`;
- `shared/contracts/schemas/agent-registration-request.schema.json`;
- `shared/contracts/schemas/agent-registration-response.schema.json`;
- `shared/contracts/schemas/agent-credential.schema.json`;
- `shared/contracts/schemas/error-envelope.schema.json`;
- `shared/contracts/examples/`.

Los schemas y OpenAPI no se duplican ni se modifican desde Android.

## DTOs y metadata

El módulo `:core:contracts` implementa:

- `AgentRegistrationRequestDto`;
- `AgentRegistrationResponseDto`;
- `AgentCredentialDto`;
- `ErrorEnvelopeDto`, `ApiErrorDto` y `ErrorDetailDto`;
- `AgentPlatformDto` con los cinco valores públicos;
- `CredentialDeliveryStateDto` con `active` y `pending`;
- path y headers públicos de enrolamiento;
- schema version y Agent Protocol `1.0.0`.

Todas las propiedades wire requeridas son no nullable y carecen de valores por
defecto. `ApiErrorDto.details` es la única excepción de valor nullable: la
propiedad continúa siendo obligatoria y acepta una lista o `null`.

Los códigos de error permanecen como `String`; el contrato no publica un enum
cerrado. Tampoco existe un valor fallback para platform o credential state.

## Secretos

Request, response y credential no son `data class`. Sus `toString()` no exponen
el enrollment token ni el material de credential y muestran únicamente el
marcador `<redacted>`. C02A no registra payloads, no persiste secretos y no usa
la credential como autenticación.

## Serialización y fixtures

Los DTOs usan el plugin Kotlin serialization 2.3.21 y
`kotlinx.serialization` 1.11.0. La dependencia JSON sólo pertenece a tests; no
hay un singleton JSON de producción.

Los tests JVM usan una instancia estricta con unknown fields, coerción y JSON
lenient deshabilitados, y nulls explícitos. Los fixtures se leen en modo lectura
desde `shared/contracts/examples/` mediante una ruta relativa al root Gradle
Android y se declaran como input de la tarea `:core:contracts:test`.

No existe un fixture canónico de `ErrorEnvelope`, de enum desconocido ni de
campo requerido ausente. Esos casos usan JSON inline mínimo dentro de tests; no
se agregan golden fixtures Android ni se altera `shared/contracts/`.

`kotlinx.serialization` valida la representación estructural, pero no sustituye
JSON Schema. En particular, UUID, UUID v4, patterns, longitudes, SemVer,
timestamps UTC, correlación entre IDs y expiración siguen bajo los validators
normativos existentes y quedan fuera de la validación productiva C02A.
La librería también admite algunas conversiones primitivas propias —por
ejemplo, un string numérico al decodificar un `Int`— aun con coerción
deshabilitada; el tipo JSON exacto continúa verificándose con los validators
normativos.

## Límites posteriores

C02B queda diferido para dominio puro y sus reglas, sin crear una dependencia
entre `domain` y `contracts`. C03 queda diferido para mapping, transporte HTTP y
serialización de producción en `core:data`.

También permanecen ausentes persistencia, Android Keystore, APIs Android,
permisos, UI, WorkManager, Foreground Service, capabilities, presence, sync,
tareas remotas, probes, tráfico, captura y replay. No se ejecutan ni se reclaman
tests instrumentados o de emulador en C02A.
