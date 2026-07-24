# C07 — coordinador de enrolamiento Android

## Estado y alcance

C07 integra los ports existentes de C03, C05 y C06 dentro de `:core:data`.
Coordina un único intento de enrolamiento en memoria, serializa el flujo para
todo el proceso, protege inmediatamente la credential aceptada y entrega a C06
únicamente metadata no secreta y un `ProtectedCredentialEnvelope`.

C07 no modifica contratos públicos, backend, OpenAPI, Room, migraciones,
schemas, C03–C06, manifests ni permisos. Tampoco incorpora UI, Activity,
Service, Receiver, Provider, launcher, WorkManager, Foreground Service,
lifecycle operativo, capabilities, probes, tareas remotas, rotación,
unenrollment, reset, delete o recuperación administrativa.

La lógica reside en `:core:data`: depende de los ports de `:core:domain` y de
C03/C06, pero nunca de `:core:platform`. `:app` compone de forma lazy el
transporte, el repositorio Room y el protector Android Keystore. Construir
`WtoApplication` o `AndroidAgentCompositionRoot` no abre Room, no inspecciona o
crea claves, no construye requests, no consume tokens, no inicia red y no crea
coroutines.

`:core:data` declara directamente `kotlinx-coroutines-core:1.8.1`; producción
usa únicamente APIs disponibles en esa versión. Los tests conservan
`kotlinx-coroutines-test:1.11.0`. Ambos artefactos ya pertenecían al grafo y a
la verification metadata aprobada; C07 no necesita regenerar locks o checksums.

## Intento efímero

`EnrollmentAttempt` se crea antes de entrar al flujo coordinado. No es
`data class`, `Parcelable` ni serializable, y su `toString()` está completamente
redactado. Conserva exactamente:

- el `EnrollmentCommand` validado;
- instalación y servidor esperados;
- token;
- idempotency key;
- correlation ID;
- `agent_reported_at`;
- display name, platform/agent version y payload resultante;
- un identificador aleatorio opaco que no contiene secretos.

El caller conserva ownership del objeto. El coordinador no regenera ninguna de
esas propiedades. Un retry manual presenta el mismo objeto vivo y
`MANUAL_SAME_LIVE_ATTEMPT_ONLY`; un intento diferente nunca hereda autorización
del anterior.

Los `String` internos de Kotlin/JVM, el request de OkHttp y las copias internas
de JVM/JCA no ofrecen zeroization garantizable. C07 no afirma lo contrario.

## Secuencia exacta

El orden productivo es:

1. adquirir cancellably el mutex global del proceso;
2. ejecutar dentro del mutex el `preflight` C06 autoritativo;
3. resolver `Conflict`, `LocalStateIncomplete`, `Corrupt`, `Unsupported` o
   `Failure` sin tocar Keystore o red;
4. si existe estado `Compatible`, resolver cualquier guard previo usando esa
   evidencia durable, ejecutar sólo `CredentialProtector.inspect()` fuera del
   main thread y devolver `AlreadyEnrolled` únicamente ante clave compatible;
5. si el estado es `Absent`, consultar el guard y ejecutar sólo
   `CredentialProtector.prepare()` fuera del main thread;
6. crear como máximo un `EnrollmentCall`;
7. registrar cancelación antes de despachar y ejecutar esa llamada bloqueante
   como máximo una vez fuera del main thread;
8. validar defensivamente una aceptación C03;
9. pasar inmediatamente `DeliveredCredential` a `protect()`;
10. validar que envelope y metadata correspondan;
11. construir `ProtectedEnrollmentWrite` sin token, plaintext, headers ni body;
12. invocar `persist()` exactamente una vez;
13. sólo ante `PersistProtectedEnrollmentResult.Failure` o una excepción
    equivalente, ejecutar como máximo un `read()` autoritativo y read-only;
14. mutar el guard sin suspensión antes de liberar el mutex;
15. liberar siempre el mutex por la semántica estructurada de `withLock`.

El mutex permanece adquirido durante Keystore, llamada remota, protección,
persistencia y reconciliación. No se adquiere al construir `EnrollmentAttempt`.

## Preflight y estado durable

El preflight precede toda operación Keystore para no crear efectos locales
cuando Room ya bloquea la operación:

| C06 | Acción C07 |
| --- | --- |
| `Absent` | autorizar con guard y ejecutar sólo `prepare()` |
| `Compatible` | resolver guard mediante evidencia durable y ejecutar sólo `inspect()` |
| `Conflict` | `LocalStateBlocked(IDENTITY_OR_SERVER_CONFLICT)` |
| `LocalStateIncomplete` | `MissingPrecondition(LOCAL_STATE_INCOMPLETE)` |
| `Corrupt` | `LocalStateBlocked(CORRUPT)` |
| `Unsupported` | `LocalStateBlocked(UNSUPPORTED)` |
| `Failure` | `LocalStateBlocked` con categoría cerrada de C06 |

C07 no crea filas C04, no cambia el servidor, no repara, borra o resetea estado
local y no inventa si un `Conflict` provino de identidad o servidor.

`AlreadyEnrolled` significa que el preflight observó un enrolamiento durable
compatible y `inspect()` observó una clave policy-compatible. No descifra ni
autentica el envelope y no afirma que la credential sea usable.

## Guard y concurrencia

Todas las factories productivas comparten un único `ProcessEnrollmentGuard`,
que contiene:

- un `Mutex` de proceso;
- `Open`;
- `RemoteOutcomeUnresolved(attemptId)`;
- `RemoteAcceptedNotDurable(attemptId)`.

El guard puede recordar el último identificador autorizado aun estando abierto
para impedir que una intención manual sustituya el objeto; sólo conserva ese
identificador opaco. Nunca conserva token, comando, request, credential,
envelope o callback. Una segunda ejecución adquiere el mismo mutex y relee
Room. En estado `Open`, un intento diferente con intención `INITIAL` puede ser
autorizado y reemplaza `lastAuthorizedAttemptId`, pero nunca puede presentarse
como retry manual del intento anterior. En `RemoteOutcomeUnresolved` o
`RemoteAcceptedNotDurable`, un intento diferente queda bloqueado; el mismo
intento sólo pasa con `MANUAL_SAME_LIVE_ATTEMPT_ONLY`.

Una evidencia durable `Compatible`, `Written`, `ExistingEquivalent`, `Replaced`
o reconciliada abre el guard. Una respuesta rechazada o un fallo
inequívocamente anterior al envío no crea ambigüedad nueva, pero tampoco borra
una ambigüedad previa del mismo intento.

Las transiciones son asignaciones síncronas, no suspensivas, dentro del mutex.
También se ejecutan ante `CancellationException`, excepciones inesperadas o
`Error`. No requieren `withContext(NonCancellable)`; su único uso en C07 es la
espera de la barrera terminal de un worker remoto que ya comenzó.

El guard sólo vive en memoria y desaparece con process death. No protege un
reinicio ni sustituye un journal durable.

## Bridge cancellable

`EnrollmentCall.execute()` es bloqueante. `EnrollmentCallAwaiter`:

- registra el handler de cancelación antes de despachar;
- usa el dispatcher IO de la factory productiva;
- llama `cancel()` como máximo una vez;
- coordina atómicamente `QUEUED`, `RUNNING`, `CANCELLED_BEFORE_START` y
  `TERMINAL`;
- usa una única reanudación de `Continuation`;
- impide que protección o persistencia comiencen después de una cancelación;
- no crea `CoroutineScope`, Job o worker permanente.

Una cancelación que gana `QUEUED -> CANCELLED_BEFORE_START` no espera y el
worker ya no puede entrar posteriormente en `execute()`. Si el worker gana
`QUEUED -> RUNNING`, la cancelación solicita `cancel()` y espera, únicamente en
`NonCancellable`, hasta observar `TERMINAL`; el mutex permanece adquirido
durante esa espera. Después, el resultado se trata conservadoramente como
potencialmente ambiguo. Si el worker observó una aceptación, el estado más
preciso es `RemoteAcceptedNotDurable`; de lo contrario es
`RemoteOutcomeUnresolved`. En ambos casos se relanza la
`CancellationException`, nunca se devuelve un resultado normal `Cancelled`.

Si un adapter defectuoso no termina después de `cancel()`, la espera terminal y
el mutex permanecen retenidos. C07 prefiere bloquear nuevos enrolamientos de
forma fail-closed antes que permitir dos operaciones remotas concurrentes.

## Ambigüedad remota y retry

La clasificación es:

| Evidencia C03 | Disposición |
| --- | --- |
| fallo de creación, `INVALID_LOCAL_REQUEST`, `INVALID_ENDPOINT` | remoto no intentado |
| DNS o conexión inequívocamente anterior al envío | fallo transitorio conocido |
| `Rejected` completamente válido | rechazo remoto conocido |
| TLS, timeout, I/O, respuesta incompleta o cancelación tras iniciar | resultado remoto no resuelto |
| respuesta inválida/incompatible | posiblemente aceptada; status `null` si C03 no lo conserva |
| `Accepted` seguida de fallo de validación, C05 o C06 | aceptada remota, no durable local |

C07 no realiza retries automáticos. La única política publicada es
`MANUAL_SAME_LIVE_ATTEMPT_ONLY`, que reutiliza exactamente el mismo intento.
No existe una duración garantizada:

1. el backend valida primero `agent_reported_at` y su clock skew configurable
   de 30 a 300 segundos, 300 por defecto;
2. valida después el token;
3. sólo entonces consulta idempotencia;
4. el replay secreto puede conservarse hasta 15 minutos.

Por lo tanto, la ventana efectiva puede ser mucho menor que el secret replay.
El mismo intento puede ser rechazado por timestamp, configuración o estado del
token. C07 no refresca `agent_reported_at`, no crea silenciosamente otro intento
y no prueba otro token.

## Aceptación, secretos y resultados

Antes de proteger, C07 vuelve a comprobar:

- identidad local esperada;
- correlation ID congelado;
- protocolo actual;
- estado exactamente `ACTIVE`;
- metadata tipada de ID y versión;
- `issuedAt <= serverReceivedAt < expiresAt`.

Después de `protect()`, valida policy, credential ID y credential version del
envelope. La credential plaintext permanece en variables locales de scope
mínimo, nunca se guarda en un field, resultado o Room y nunca entra en logs o
excepciones públicas. Los callbacks productivos no la conservan.

La API cerrada devuelve `Enrolled`, `AlreadyEnrolled`,
`MissingPrecondition`, `InvalidConfiguration`, `LocalStateBlocked`,
`KeyIncompatible`, `PlatformFailure`, `RemoteRejected`,
`KnownTransientFailure`, `RemoteOutcomeAmbiguous`, `ResponseIncompatible`,
`ProtectionFailure` o `PersistenceFailure`. Cada fallo tiene un único `reason`
enum, disposiciones cerradas y `null` para status desconocido. Ningún resultado
contiene token, credential, nonce, ciphertext, AAD o envelope.

## Persistencia, `Replaced` y reconciliación

El mapping C06 es:

| C06 | Resultado C07 |
| --- | --- |
| `Written` | `Enrolled(NEWLY_WRITTEN)` |
| `ExistingEquivalent` | `Enrolled(EXISTING_EQUIVALENT)` |
| `Replaced` | `Enrolled(REPLACED)` + `UNEXPECTED_DURABLE_REPLACEMENT` |
| demás resultados definitivos | fallo cerrado, remoto aceptado no durable |

`Replaced` ya prueba que C06 escribió y verificó estado durable. Devolver un
fallo simple falsearía el estado observable. Es anómalo para enrolamiento
inicial y puede indicar carrera o cambio concurrente.

Después de una persistencia incierta se permite una sola relectura. La
equivalencia exige la misma instalación, servidor, identidad backend,
protocolo, `serverReceivedAt`, metadata completa, estado `ACTIVE`, y policy,
alias, credential ID/version válidos del envelope. Igual que C06, no exige
nonce/ciphertext byte-idénticos para un candidato criptográficamente equivalente.

Una lectura equivalente devuelve `RECONCILED_AFTER_FAILURE`. Ausencia,
corrupción, versión no soportada, fallo de lectura o un `Compatible` no
equivalente no afirman éxito y conservan el guard bloqueante. Nunca se ejecuta
un segundo POST, `protect()` o `persist()`.

## Atomicidad y recuperación

C07 reduce ventanas de fallo, pero no puede crear atomicidad distribuida entre
backend, Android Keystore y SQLite:

- un resultado remoto ambiguo puede haber consumido el token;
- una aceptación puede quedar sin protección o sin persistencia local;
- el proceso puede morir antes de actualizar el guard;
- un commit Room puede ocurrir antes de que el caller reciba el éxito.

El próximo preflight recupera un commit durable compatible, pero no existe
endpoint de consulta/reconciliación remota ni recovery destructivo en C07. El
journal durable y la reconciliación remota quedan en
`FW-MOB-004`.

## Evidencia y límites

Las suites host cubren orden, matrices C03/C05/C06, una sola invocación, guard,
dos coordinadores, retry del mismo intento, intentos diferentes, carreras de
cancelación, `Error`, reconciliación y redacción. Los tests de app comprueban
composición lazy sin ejecutar enrolamiento.

No constituyen evidencia de Android Keystore real, KeyMint, TEE/StrongBox,
provider/OEM, process death real, restart, emuladores API 29/35/36/36.1 ni
instrumentación. Esas validaciones siguen diferidas. C08–C11 requieren
validación de alcance posterior; C07 no hace su rebaseline.
