# Fase 08 — Contratos wire y dominio Android

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

## Alcance implementado en C02B

C02B incorpora únicamente el dominio base de identidad, configuración segura,
secretos, metadata de credenciales y aceptación factual de enrolamiento. El
módulo `:core:domain` continúa siendo Kotlin/JVM puro y no depende de
`:core:contracts`; la separación impide que DTOs wire, nombres serializados o
defaults de transporte se conviertan accidentalmente en invariantes de dominio.

La validación usa `ValidationResult`, un tipo sellado con `Valid` e `Invalid`, y
errores puros con códigos, descripciones y enums cerrados. Los errores nunca
guardan el input original, URLs, tokens, credentials, payloads ni mensajes de
excepciones. No representan HTTP, disponibilidad de transporte ni decisiones de
retry.

### Identidad y versiones

`InstallationId`, `AgentId`, `DeviceId` y `CredentialId` aceptan UUID canónico
lowercase, variante RFC y versiones 1–8. Rechazan uppercase, representaciones no
canónicas, UUID cero y versiones fuera de ese rango. Sólo `InstallationId`
puede generarse localmente; IDs de agent, device y credential son asignados por
backend. `IdempotencyKey` exige UUID v4 y puede generarse. `CorrelationId` es un
string tipado de 1–128 caracteres bajo
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}` y conserva case.

`LocalInstallationIdentity` representa la instalación local;
`BackendAgentIdentity` representa la asignación remota completa de agent y
device. `IdentityState` sólo admite `Absent`, `LocalOnly` y `Assigned`, sin IDs
backend parciales ni sentinels. Un recovery futuro puede conservar IDs backend
y vincular una instalación distinta; C02B sólo mantiene la separación y no
ejecuta persistencia, startup, reconciliación o recovery.

`SemanticVersion` usa componentes `BigInteger`, formato
`major.minor.patch`, prerelease opcional y comparación SemVer 2.0. Rechaza build
metadata, leading zeros y prerelease inválido. `SchemaVersion` y
`ProtocolVersion` separan sintaxis de soporte y aceptan actualmente `1.0.0`;
`AgentVersion` sólo valida sintaxis y no lee `BuildConfig`.

El regex contractual `common.schema.json#/$defs/semver` puede aceptar algunos
prerelease que SemVer estricto rechaza, por ejemplo identificadores vacíos o
numéricos con leading zero. C02B no modifica el contrato. C03 deberá convertir
esa diferencia en una violación contractual explícita y no normalizarla ni
aceptarla silenciosamente.

### Configuración HTTPS e IDN

`ServerConfiguration` contiene únicamente un `ServerBaseUrl`. La URL debe ser
absoluta, jerárquica y HTTPS, con host y sin userinfo, query o fragment. El
puerto 443 explícito se elimina; otros puertos válidos se conservan. El path es
un directorio, termina en `/`, conserva case y sólo admite segmentos
`[A-Za-z0-9._~-]+`; se rechazan `//`, segmentos `.`/`..`, backslash,
percent-encoding y whitespace.

Hosts DNS se canonicalizan a lowercase. Input IDN Unicode se valida con
`IDN.toASCII(..., USE_STD3_ASCII_RULES)` y se almacena en punycode sólo cuando
no contiene caracteres de desviación IDNA2003. `U+00DF`, `U+03C2`, `U+200C` y
`U+200D` se rechazan fail-closed antes de que el procesamiento legado pueda
sustituirlos o eliminarlos; punycode ASCII explícito continúa permitido. IPv4
admite sólo cuatro octetos decimales canónicos sin leading zeros; se rechazan
las notaciones hexadecimal y octal, los enteros compactos, los componentes
abreviados y Unicode que normalice a una representación numérica. Hosts DNS
alfanuméricos legítimos continúan permitidos. IPv6 exige corchetes, rechaza
scope/zone ID y se canonicaliza. `localhost` es válido. Esta política sólo
valida configuración: no realiza DNS, networking, reachability, redirects, TLS
runtime ni configura un trust mode, y no implementa enrolamiento funcional.
HTTPS y el system trust store quedan como invariantes para boundaries futuros.

### Secretos y credenciales

`EnrollmentToken` y `AgentCredentialSecret` validan las longitudes, prefijos,
locator UUID y segmento base64url publicados. Son clases normales: raw privado,
igualdad referencial, sin `copy`/`componentN`, serialización o getter. Sólo
`useSecret { ... }` entrega el valor al callback; `toString()` y errores quedan
redactados. `AgentCredentialSecret` expone únicamente su `CredentialId`; el
locator del token de enrolamiento no tiene un tipo público. Como el material se
recibe en `String`, C02B no promete zeroization.

`CredentialMetadata` contiene ID, versión positiva, `issuedAt`, `expiresAt` y
estado `ACTIVE` o `PENDING`; exige `expiresAt > issuedAt` y nunca contiene el
secreto. `usabilityAt(now)` produce `Expired` cuando `now >= expiresAt`,
`Usable` sólo para active no expirada y `PendingActivation` para pending no
expirada. `DeliveredCredential` combina metadata y secreto sólo si ambos IDs
coinciden, conserva redacción y no implica almacenamiento o autenticación.

### Aceptación factual

`BackendEnrollmentAcceptance` conserva `LocalInstallationIdentity`,
`BackendAgentIdentity`, `DeliveredCredential`, `serverReceivedAt` y
`ProtocolVersion`. Describe únicamente una aceptación backend ya validada por
un boundary futuro. No representa un status HTTP, persistencia local,
autenticación exitosa, retry, recovery ni enrolamiento durable.

No existe `EnrollmentState`, `PreparedEnrollment`, `Enrolled` o
`RecoveryRequired`, ni una máquina de transiciones.

## Límites posteriores

C03 queda diferido para mapping DTO/dominio, serialización de producción,
transporte HTTP y sus errores en `core:data`. C02B no introduce mapping, JSON,
red, persistencia, filesystem, Room, Keystore, DataStore, SharedPreferences,
repositorios, APIs Android ni UI.

También permanecen ausentes persistencia, Android Keystore, APIs Android,
permisos, UI, WorkManager, Foreground Service, capabilities, presence, sync,
tareas remotas, probes, tráfico, captura y replay. No se ejecutan ni se reclaman
tests instrumentados o de emulador en C02A/C02B; para el dominio Kotlin/JVM puro
no aplican.
