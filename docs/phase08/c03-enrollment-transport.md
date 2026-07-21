# Fase 08 — C03 mapping y transporte HTTPS de enrolamiento Android

## Alcance implementado

C03 integra los DTO wire de `:core:contracts` con el dominio de `:core:domain`
exclusivamente desde `:core:data`. Incorpora construcción del comando, mapping,
JSON estricto, prevalidación, transporte HTTPS directo con OkHttp, cancelación y
una traducción cerrada de respuestas. No persiste la aceptación o la credential
y no implementa el ciclo funcional del agente.

`EnrollmentCommand.create` es el único punto de construcción transmisible. El
caller debe aportar configuración HTTPS, identidad local, idempotency key,
correlation ID, token, nombre, versión de plataforma, versión del agente y
timestamp. Un valor requerido ausente, vacío o fuera de contrato falla antes de
crear el comando; C03 no inventa cero, string vacío, `unknown` ni defaults. Los
literales provistos por el caller se evalúan sólo contra el contrato: `unknown`,
`UNKNOWN`, `0`, epoch y strings de whitespace no están reservados, no se
normalizan y se preservan exactamente cuando cumplen sus longitudes.

## Request y endpoint

El mapper genera los once campos requeridos del contrato v1:

- `schema_version`, `protocol_min_version` y `protocol_max_version`: `1.0.0`;
- `platform`: `android`;
- `idempotency_key`: el mismo valor provisto para `Idempotency-Key`;
- token, installation ID, display name, platform version, agent version y
  `agent_reported_at`: los valores validados del comando.

Después de serializar, `:core:data` vuelve a comprobar el objeto exacto, tipos,
constantes y correspondencia con el comando. El payload debe ser no vacío y de
como máximo 32 KiB antes de crear la llamada.

El endpoint agrega los segmentos `api/v1/agent-enrollments` sobre el path base,
sin resolver un path absoluto. Por ejemplo, `https://host/Tenant/` produce
`https://host/Tenant/api/v1/agent-enrollments`. Se preservan HTTPS, host
canónico, puerto, capitalización y segmentos ya validados. No se aceptan HTTP,
userinfo, query, fragment, cambio de host ni redirects. Si el path base ya
termina en los tres segmentos efectivos `api/v1/agent-enrollments`, con o sin
slash final y aunque exista un prefijo previo, la construcción falla como
`INVALID_ENDPOINT`. La comparación usa los segmentos decodificados
individualmente por OkHttp, por lo que escapes equivalentes de caracteres no
reservados no evaden la detección; un `%2F` decodificado permanece dentro de su
segmento lógico y no se interpreta como separador. Coincidencias parciales,
substrings o con distinto case no se confunden con ese sufijo.

La solicitud usa `POST`, `Content-Type: application/json`,
`Accept: application/json`, `Idempotency-Key` y `X-Correlation-ID`. No usa
`Authorization`, `Cookie` ni `Proxy-Authorization`.

## JSON y respuestas

Existe una única instancia JSON de producción con:

- `ignoreUnknownKeys = false`;
- `isLenient = false`;
- `coerceInputValues = false`;
- `explicitNulls = true`;
- `exceptionsWithDebugInfo = false`;
- enums case-sensitive, sin nombres alternativos ni números especiales.

Antes de deserializar, una prevalidación acotada exige objeto raíz, conjunto
exacto de keys, presencia, nullability, tipos JSON exactos, objetos anidados,
integers léxicos reales, enums, longitudes, cardinalidades, UUID, timestamps UTC,
versiones, formato del secreto y consistencia entre credential ID y secreto.
También valida `details` como `null` o array contractual sin conservarlo.

Los timestamps wire siguen un perfil UTC compartido para request, response y
credenciales: año de cuatro dígitos entre 0001 y 9999, fecha y hora calendario
válidas, separador `T`, sufijo `Z` mayúscula, sin offsets ni trailing content y
un máximo de 32 code points. Schema y backend rechazan leap seconds,
`24:00:00`, fechas inexistentes y años cero o extendidos. El parser backend
tolera `z` minúscula, offsets y ausencia de zona donde el schema no. Schema y
backend pueden aceptar además `t` minúscula como separador; Android C03 exige
deliberadamente `T` mayúscula como política fail-closed y no la normaliza de
forma silenciosa. C03 aplica la intersección contractual restante y exige `Z`
final mayúscula. Fracciones de cero a nueve dígitos se convierten exactamente.
Fracciones de diez u once dígitos sólo se aceptan
si todo dígito posterior al noveno es cero; únicamente se eliminan esos ceros
sin cambiar el instante. Cualquier precisión subnanosegundo no nula falla de
manera cerrada: `Instant` no puede representarla y no se trunca ni redondea.

Kotlin Serialization conserva silenciosamente el último valor ante propiedades
duplicadas. Por eso un scanner del JSON crudo, limitado a 64 niveles y al body
ya acotado, rechaza de manera fail-closed cualquier clave duplicada en objetos
raíz o anidados, incluso si una aparición usa escapes Unicode. También se
rechazan BOM, trailing tokens, UTF-8 inválido, JSON malformado y body vacío o de
sólo whitespace.

Sólo se admite `application/json` sin parámetros o con un único
`charset=utf-8`, case-insensitive. MIME ausente, duplicado, otro charset,
parámetros adicionales o `application/problem+json` son inválidos.

El body se lee incrementalmente hasta el byte 65.537 después de la
descompresión transparente. 65.536 bytes son válidos; 65.537 producen
`RESPONSE_TOO_LARGE`. `Content-Length` permite rechazo temprano, pero no es la
única defensa. La respuesta y sus streams siempre se cierran.

## Correlación y resultados cerrados

Toda respuesta procesable exige exactamente un `X-Correlation-ID`, no vacío,
válido y equivalente al solicitado. Para errores también debe cumplirse:

`request header = response header = error.correlation_id`.

Una ausencia, duplicación, valor inválido o contradicción siempre produce
`Failed`, nunca `Rejected`.

Los únicos resultados públicos son:

- `Accepted`: aceptación de dominio validada y correlation ID validado;
- `Rejected`: razón cerrada, status normativo y correlation ID validado;
- `Failed`: una razón local o de transporte cerrada.

Los rechazos normativos son `401` autenticación/token/reloj, `409` conflicto,
`413` request demasiado grande, `422` contrato, `429` rate limit y `503`
servicio no disponible. Se clasifican primariamente por status y sólo se emite
`Rejected` si el envelope completo es válido. El código del envelope se valida,
pero no reemplaza al status; esto tolera de forma segura el actual
`login_rate_limited` del backend en 429. `message` y `details` nunca se exponen.

`201` es el único éxito. Otros 2xx, 4xx o 5xx son `UNEXPECTED_STATUS`; todo 3xx
es `REDIRECT` y nunca genera una segunda solicitud.

Las razones `Failed` son `INVALID_LOCAL_REQUEST`, `INVALID_ENDPOINT`,
`REDIRECT`, `UNEXPECTED_STATUS`, `INVALID_CONTENT_TYPE`, `EMPTY_BODY`,
`RESPONSE_TOO_LARGE`, `MALFORMED_JSON`, `INVALID_RESPONSE_SHAPE`,
`INVALID_RESPONSE_SEMANTICS`, `MISSING_CORRELATION`, `CORRELATION_MISMATCH`,
`DNS`, `TLS`, `CONNECTION`, `TIMEOUT`, `CANCELLED`, `INCOMPLETE_RESPONSE` e
`IO`. Ninguna conserva body, URL, mensaje original, `Throwable` o causa.

## Política HTTP, TLS y cancelación

El cliente compartido usa OkHttp 5.3.2 directamente, con 10 s de conexión, 20 s
de lectura, 20 s de escritura y 30 s totales. Desactiva retry de conexión, fast
fallback, redirects HTTP/HTTPS, cache, cookies y authenticators; no contiene
interceptors ni logging. Mantiene DNS, trust store, trust manager y hostname
verifier del sistema. No configura pinner, CA privada ni cleartext.

Cada `EnrollmentCall` puede ejecutarse una sola vez. `cancel()` es thread-safe y
delega a `Call.cancel()`. La operación es bloqueante y debe invocarse fuera del
main thread. `CANCELLED` y `TIMEOUT` describen el resultado local; si ocurren
después del envío no afirman que el servidor no procesó la solicitud.

La clasificación determinista es: cancelación explícita, DNS, TLS, timeout,
conexión, respuesta EOF/protocolo/gzip incompleta y finalmente I/O genérico.

## AndroidX Startup y manifest

OkHttp 5.3.2 incorpora AndroidX Startup transitivamente. `:app` elimina
explícitamente `androidx.startup.InitializationProvider` mediante manifest merge
y registra la `Application` mínima `WtoApplication`. Su único comportamiento es
delegar `OkHttp.initialize(applicationContext)` a la fachada pública
`EnrollmentHttpRuntime` de `:core:data`; no inicia red, enrolamiento, observación
o features.

`:core:data` declara únicamente `android.permission.INTERNET` y `:app` mantiene
`usesCleartextTraffic=false`. C03 no agrega Activity, Service, Receiver,
Provider, launcher, CA privada ni network security config.

## Pruebas y reproducción

Las suites JVM de `:core:data` cubren mapping y golden request; ausencia de
fallback; literales válidos preservados; perfil timestamp y precisión exacta;
duplicación del endpoint; JSON válido e inválido; duplicados; límites; status y
MIME; correlación; redacción; política del cliente; gzip; cortes de body; DNS,
conexión, timeout y cancelación; y TLS con certificados efímeros en memoria.
MockWebServer3 no accede a Internet y el trust de certificados de prueba sólo se
inyecta en clientes internos del test.

Los gates aplicables son:

```powershell
.\gradlew.bat --no-daemon :core:data:testDebugUnitTest
.\gradlew.bat --no-daemon :core:contracts:test :core:domain:test
.\gradlew.bat --no-daemon :core:data:lintDebug :app:lintDebug
.\gradlew.bat --no-daemon :app:processDebugMainManifest :app:assembleDebug
```

Después de una resolución controlada, las tareas Android se repiten con
`--offline`; locks y verification metadata deben quedar idénticos.

Resultado validado para este corte:

- `:core:data`: 61 tests en 6 suites; cero fallos, errores o skips;
- `:core:contracts`: 31 tests en 4 suites; cero fallos, errores o skips;
- `:core:domain`: 97 tests en 8 suites; cero fallos, errores o skips;
- lint de `:core:data` y `:app`, manifest processing y `:app:assembleDebug`:
  completados;
- manifest fusionado: un permiso `INTERNET`, cleartext desactivado,
  `WtoApplication` y cero Activity, Service, Receiver, Provider o intent filter;
- validadores OpenAPI, contratos, compatibilidad y repositorio: completados;
- pase Gradle offline: completado sin alterar locks ni verification metadata.

## Fuera de alcance y deudas conocidas

C03 no implementa Room, Keystore, almacenamiento, rotación de credenciales,
capabilities, observadores Android, WorkManager, Foreground Service, UI,
presence, telemetría, retry scheduler ni ejecución persistente. Las tareas
remotas pertenecen a Fase 10, los probes a Fase 11 y CI Android a C13.

Se conservan como deudas, sin modificar contratos o backend:

- UUID v4 exigido por Android para installation/idempotency frente al UUID más
  general de parte del contrato público;
- SemVer 2.0 Android más estricto que el regex compartido;
- precisión subnanosegundo no nula permitida por schema/backend pero no
  representable por `Instant`; C03 la rechaza sin truncar ni redondear;
- `login_rate_limited` emitido por backend para el 429 de enrolamiento;
- generación backend de correlation ID cuando OpenAPI lo exige al caller;
- diferencias de endurecimiento con el agente desktop;
- documentación global diferida a C14;
- ausencia de CI Android hasta C13.
