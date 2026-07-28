# Android agent

Este directorio contiene el bootstrap reproducible C01, los contratos wire de
enrolamiento C02A, el dominio base puro C02B, la integración inicial de
enrolamiento C03, la base Room C04, la protección Android Keystore C05, la
persistencia del enrolamiento protegido C06 y el coordinador C07. El proyecto
incorpora en C08 la publicación explícita y durable del Capability Manifest,
y en C09 un observer local, pasivo y explícito de conectividad/Wi-Fi. Sigue sin
pantallas, actividades, servicios, WorkManager, probes ni lifecycle operativo
automático. C07 integra en memoria C03–C06; C08 publica un snapshot de 15
capabilities sin reinterpretarlo por C09.

## Toolchain

- Temurin JDK 17.0.19+10.
- Java y Kotlin bytecode 17.
- Gradle Wrapper 8.13.
- Android Gradle Plugin 8.13.2.
- Kotlin y Kotlin Gradle Plugin 2.3.21.
- Compose Compiler plugin 2.3.21, declarado pero no aplicado en C01.
- Compose BOM 2026.06.01, registrada para una fase posterior y no resuelta.
- `compileSdk` Android 36.1, `targetSdk` 36 y `minSdk` 29.

El minor API level usa la sintaxis tipada de AGP 8.13.2:

```kotlin
compileSdk {
    version = release(36) {
        minorApiLevel = 1
    }
}
```

No se fija manualmente la versión de Build Tools; AGP selecciona su versión
compatible.

## Módulos

- `:app`: ensamblado Android mínimo; puede depender de todos los módulos core.
- `:core:contracts`: módulo Kotlin/JVM puro con los DTOs de enrolamiento C02A y
  del Capability Manifest/ack C08.
- `:core:domain`: módulo Kotlin/JVM puro con identidad, configuración segura,
  secretos, credenciales, aceptación factual de enrolamiento C02B y el port y
  modelos criptográficos puros C05, el catálogo determinista C08 y los modelos,
  perfiles y lifecycle del observer C09.
- `:core:data`: biblioteca Android con mapping, JSON estricto y transporte HTTPS
  de enrolamiento C03, persistencia local C04, el repositorio Room v2 C06 y el
  coordinador C07 y, en C08, canonicalización, publicación HTTPS y Room v3 para
  accepted/pending; depende de domain y contracts, nunca de platform.
- `:core:platform`: biblioteca Android con el adapter Android Keystore/AES-GCM
  C05, el facts provider acotado a
  `Build.VERSION.RELEASE`/`FEATURE_WIFI` C08 y el facade/mapper/observer pasivo
  C09; depende únicamente de domain.

C07 agrega `AndroidAgentCompositionRoot`: compone lazy el cliente C03, el
repositorio C06, el protector C05 y la factory pública del coordinador. La
construcción y `Application.onCreate()` no abren Room o Keystore, no crean
requests, no consumen tokens y no inician coroutines o red.

C08 agrega otro lazy thread-safe al mismo composition root. Recibe exactamente
`BuildConfig.VERSION_NAME` como `AgentVersion`; habilitar la generación normal
de `BuildConfig` es el único cambio de configuración de build. Construir el root
continúa sin abrir Room, tocar Keystore, crear coroutines, observar Wi-Fi o
publicar.

C09 agrega un tercer lazy thread-safe. Memoizar el observer no crea
`HandlerThread`, no registra callbacks y no observa estado; sólo un `start()`
explícito lo activa. `WtoApplication.onCreate()` permanece intacta.

## Contratos wire C02A

`:core:contracts` representa exclusivamente el request, response, credential y
error envelope publicados en `shared/contracts/`. Sus modelos usan
`kotlinx.serialization` 1.11.0, propiedades requeridas sin defaults y enums
wire cerrados. Request, response y credential son clases normales con
`toString()` redactado; el token y la credential nunca se incluyen en esa
representación.

Los tests JVM configuran JSON estricto y leen directamente los fixtures
canónicos de `shared/contracts/examples/`, declarado como input de la tarea
Gradle. No se copian ni modifican fixtures. La deserialización valida forma,
campos requeridos, nullability y enums; JSON Schema continúa siendo la autoridad
para UUID, patterns, longitudes, SemVer, timestamps y demás semántica.

C02A no implementa dominio, persistencia, Keystore, enrolamiento durable, UI ni
tareas remotas. El dominio puro se incorpora por separado en C02B y el mapping y
transporte inicial se implementan en C03 sin alterar `:core:contracts`.

## Dominio puro C02B

`:core:domain` no depende de `:core:contracts` ni de ningún módulo Android.
Tampoco importa `android.*`, `BuildConfig`, serialización, JSON, red,
persistencia o filesystem. Sus factories devuelven `ValidationResult.Valid` o
`ValidationResult.Invalid` con errores cerrados, estables y sin raw input.

C02B incorpora:

- IDs tipados: los UUID son canónicos lowercase, variante RFC, versiones 1–8 y
  no aceptan el UUID cero; `IdempotencyKey` exige específicamente UUID v4 y
  `CorrelationId` conserva case bajo el patrón contractual.
- `SemanticVersion` numérica con `BigInteger`, comparación SemVer 2.0 y
  prerelease estricto; schema y Agent Protocol soportan actualmente `1.0.0`,
  mientras `AgentVersion` sólo valida sintaxis y se inyectará más adelante.
- `ServerBaseUrl` HTTPS absoluta y canónica: sin userinfo, query, fragment,
  escapes ni paths ambiguos; DNS alfanumérico legítimo se guarda lowercase e
  IDN sin caracteres de desviación IDNA2003 se convierte a punycode. Se rechazan
  fail-closed `U+00DF`, `U+03C2`, `U+200C` y `U+200D`; punycode ASCII explícito
  continúa permitido. IPv4 admite sólo cuatro octetos decimales canónicos sin
  ceros iniciales: rechaza hexadecimal, octal, enteros compactos, componentes
  abreviados y Unicode normalizado a una representación numérica. IPv6 exige
  corchetes. Esta validación no realiza DNS, networking, reachability ni
  negociación TLS, y no implementa enrolamiento funcional.
- `EnrollmentToken` y `AgentCredentialSecret` como clases de igualdad
  referencial, raw privado, `toString()` redactado y acceso únicamente mediante
  `useSecret`. `String` no ofrece zeroization garantizable; C02B no afirma lo
  contrario.
- Metadata de credential segura, expiración con `Instant` recibido por el
  caller y usabilidad factual `Usable`, `PendingActivation` o `Expired`.
  `now >= expiresAt` siempre es `Expired`; una credential pending nunca es
  usable.
- Separación entre `LocalInstallationIdentity` y `BackendAgentIdentity`, con
  `IdentityState.Absent`, `LocalOnly` o `Assigned`. Recovery puede conservar la
  asignación backend y asociar otra instalación, pero C02B no ejecuta ese flujo.
- `BackendEnrollmentAcceptance` como hecho ya validado por un boundary futuro.
  Conserva la instalación usada, la asignación backend, la credential entregada,
  tiempo del servidor y protocolo, pero no representa persistencia,
  autenticación exitosa, recovery ni enrolamiento durable.

No existe `EnrollmentState` ni una máquina de transiciones. Una respuesta del
backend no convierte por sí sola al agente en `Enrolled`: C03 produce una
aceptación factual en memoria, pero no incorpora retry, Room, DataStore,
SharedPreferences, Android Keystore, UI, WorkManager, Foreground Service ni
tareas remotas.

El regex SemVer publicado en `shared/contracts` admite algunas formas de
prerelease que SemVer 2.0 estricto rechaza, como identificadores vacíos o
numéricos con ceros iniciales. Los contratos normativos no se cambian en C02B o
C03; la construcción local falla de manera cerrada y la diferencia queda como
deuda de paridad contractual, nunca se normaliza silenciosamente.

Los tests de C02B son JVM puros. Tests instrumentados y emuladores no aplican y
no se ejecutan en este corte.

## Integración de enrolamiento C03

`:core:data` convierte un comando completo y validado en el DTO C02A, verifica
el JSON serializado y ejecuta exactamente un `POST` contra el endpoint relativo
`api/v1/agent-enrollments`. La construcción conserva scheme, host, puerto,
capitalización y todos los segmentos del base path HTTPS. El caller aporta
`Idempotency-Key` y `X-Correlation-ID`; la primera se repite idéntica en el
payload. No se envían `Authorization`, cookies ni `Proxy-Authorization`.

La instancia de JSON de producción rechaza propiedades desconocidas, coerción,
leniencia, nombres alternativos, enums con otra capitalización y valores
numéricos especiales. Una prevalidación distingue ausencia, `null`, tipo JSON y
semántica; un scanner acotado rechaza claves duplicadas en cualquier objeto,
incluidas claves equivalentes escritas con escapes. El request no puede superar
32 KiB. Cada body de respuesta se lee incrementalmente hasta un máximo de
65.536 bytes descomprimidos; el byte 65.537 falla de manera cerrada.

El transporte usa una única instancia compartida de OkHttp 5.3.2, sin Retrofit,
redirects, retry de conexión, fast fallback, cache, cookies, authenticators ni
interceptors. Conserva DNS, trust manager y hostname verifier del sistema, no
agrega CA privada ni certificate pinning y admite sólo HTTPS. Sus timeouts son
10 s de conexión, 20 s de lectura, 20 s de escritura y 30 s para la llamada
completa. La operación es bloqueante y debe ejecutarse fuera del main thread;
`cancel()` delega a la llamada real. Un timeout o cancelación posterior al envío
deja indeterminado si el backend procesó la solicitud.

Sólo `201` puede producir `Accepted`. Los estados `401`, `409`, `413`, `422`,
`429` y `503` producen `Rejected` únicamente con envelope, MIME y correlación
completamente válidos; cualquier otro status o body inválido produce `Failed`.
Para toda respuesta procesable debe existir un único `X-Correlation-ID` válido e
idéntico al solicitado; en errores también debe coincidir con
`error.correlation_id`. Los mensajes, details, cuerpos, URLs y excepciones no se
retienen en resultados públicos ni en representaciones textuales.

OkHttp incorpora AndroidX Startup transitivamente. El manifest de `:app`
elimina explícitamente su `InitializationProvider` y `WtoApplication` llama a
la inicialización pública soportada mediante `EnrollmentHttpRuntime`, sin
exponer tipos OkHttp a `:app` ni iniciar tráfico o features. El único permiso
agregado es `android.permission.INTERNET`, declarado por `:core:data`; cleartext
permanece desactivado.

La referencia detallada, taxonomías, cobertura y deudas conocidas están en
[`docs/phase08/c03-enrollment-transport.md`](../../docs/phase08/c03-enrollment-transport.md).

## Persistencia local Room C04/C06

`:core:data` incorpora una base llamada `wto-agent.db`, ubicada mediante la API
pública SQLite/AndroidX bajo `applicationContext.noBackupFilesDir`. C04 publicó
Room v1 con dos tablas y ocho columnas para instalación local, servidor actual
y timestamps `(epoch seconds, nanoseconds)`. C06 migra explícitamente a v2 y
agrega sólo `protected_enrollment`, vinculada por el mismo singleton a ambas
tablas C04. El schema v1 permanece byte-idéntico y v2 no hace backfill.

La tabla C06 conserva identidad backend, protocolo, tiempos y metadata de una
credential exactamente `ACTIVE`, junto con crypto version, alias, nonce y
sealed credential C05. No persiste token, plaintext, claves, headers ni
request/response JSON. Un state `PENDING` almacenado se clasifica
`Unsupported`; state desconocido o estructura inválida es `Corrupt`.

La factory pública captura `applicationContext` y entrega ambos repositorios
lazy; la base no se construye ni abre hasta la primera operación y existe una
única instancia por proceso. Entities, DAO, database y helper permanecen
`internal`. Las lecturas y escrituras C06 son transaccionales, releen el estado
antes del commit y preservan byte por byte el envelope en equivalencia. Las
consultas en main thread siguen prohibidas, WAL está fijado y no existen delete,
reset, replace ni fallback destructivo.

El helper usa `noBackupDirectory(true)`, deshabilita recuperación con pérdida de
datos e intercepta corrupción sin delegar al callback destructivo. La app
mantiene `allowBackup=false` y suma exclusiones legacy y Android 12+ para cloud
y device transfer. Tests JVM herméticos usan Room/SQLite real mediante
Robolectric 4.16.1, SDK 29 exacto y resolución offline del artifact preparado
por Gradle.

La base C04 y sus límites originales se detallan en
[`docs/phase08/c04-room-persistence.md`](../../docs/phase08/c04-room-persistence.md).

## Protección criptográfica C05

`:core:domain` define `CredentialProtector`, policy y crypto version cerradas,
un envelope v1 no serializable y el AAD binario canónico. `:core:platform`
implementa una factory lazy y sin `Context`, solicita una clave AES-256 al
provider `AndroidKeyStore` y exige `encoded == null` al inspeccionarla bajo el
alias fijo
`com.wifitestorchestrator.agent.credential.aead.v1`, y AES-GCM con nonce de 12
bytes y tag de 128 bits. Cada operación usa un `Cipher` nuevo y debe ejecutarse
fuera del main thread.

La no exportabilidad efectiva del provider real no se afirma en C05: requiere
evidencia instrumentada C12.

El plaintext contractual de 89 bytes se convierte a ASCII sin replacement,
sólo vive en buffers acotados y se limpia best-effort. El descifrado entrega un
`AgentCredentialSecret` validado únicamente dentro de un callback `Unit`; una
captura fuera del callback viola el contrato. JVM/Kotlin/JCA pueden conservar
copias internas que no son zeroizables con garantía.

Keystore almacena la clave, no el bearer credential. C05 produce en memoria un
envelope con crypto version, alias, credential ID/version, nonce y sealed
credential. C06 escribe ese envelope ya protegido en Room v2 junto con identidad
y metadata, sin depender de `CredentialProtector` ni recibir el plaintext.

La validación de una clave existente es fail-closed. Android recién expone
`KeyInfo.isUnlockedDeviceRequired()` en API 36.1. En API 29–36.0 C05 conserva el
atributo como `NOT_OBSERVABLE` y aplica una compatibilidad acotada al alias fijo
v1 sólo cuando todos los demás atributos observables son exactos; no afirma que
el valor `false` haya sido observado. Desde API 36.1 exige evidencia positiva
`NOT_REQUIRED` y no aplica ese fallback. Robolectric SDK 29 y seams explícitos
validan la policy y el lifecycle host en los límites 29/35/36.0/36.1, pero no
representan el provider `AndroidKeyStore`; la evidencia real, KeyMint, hardware,
reboot e invalidación queda `NOT RUN` hasta C12.

La policy, formato AAD, golden vector, taxonomía de errores, threat model,
compatibilidad por API y matriz de evidencia están en
[`docs/phase08/c05-android-keystore.md`](../../docs/phase08/c05-android-keystore.md).

## Persistencia del enrolamiento protegido C06

`ProtectedEnrollmentRepository` expone `preflight`, `read` y `persist`. Sus
resultados cerrados distinguen ausencia, fila compatible, primera escritura,
equivalencia, reemplazo, conflicto, rollback, candidato `PENDING`, corrupción,
estado no soportado y fallo de almacenamiento.

Una rotación sólo reemplaza una credential con ID diferente, versión superior,
state `ACTIVE` y la misma identidad backend. Mismo ID con versión diferente o
IDs diferentes con igual versión son conflictos; una versión inferior nunca
sobrescribe una superior. Un write equivalente no reemplaza el envelope aunque
el nonce aleatorio produzca otro ciphertext.

Después de un enrolamiento compatible, la URL del servidor queda inmutable:
la misma URL es idempotente y una diferente devuelve `Conflict`. Una fila
`Corrupt` o `Unsupported` bloquea la operación sin mutar nada.

C06 garantiza atomicidad SQLite, no atomicidad entre backend, Keystore y Room.
C07 adquiere un mutex global de proceso, repite el preflight dentro de él y lo
mantiene durante Keystore, request único, protección, persistencia y una posible
reconciliación read-only. El guard de ambigüedad es intencionalmente no durable.

Room no cifra el archivo completo. El bearer secret queda protegido por el
envelope AES-GCM C05; sólo nonce y ciphertext se escriben como BLOB. La
arquitectura, schema de 19 columnas, clasificación, reglas de concurrencia,
migración, seguridad y límites se documentan en
[`docs/phase08/c06-protected-enrollment-persistence.md`](../../docs/phase08/c06-protected-enrollment-persistence.md).

## Coordinador de enrolamiento C07

`EnrollmentAttempt` congela token, idempotency key, correlation ID,
`agent_reported_at`, identidad, servidor y payload. Sólo un retry manual con ese
mismo objeto vivo está permitido; C07 no promete una ventana de 15 minutos,
porque clock skew y validación del token preceden al replay idempotente del
backend.

El preflight C06 siempre ocurre antes de Keystore. `Absent` usa sólo
`prepare()`; `Compatible` usa sólo `inspect()` y puede devolver
`AlreadyEnrolled` sin descifrar el envelope. TLS, timeout, I/O, respuesta
incompleta o cancelación posterior a `execute()` bloquean el guard de proceso;
una aceptación seguida de fallo C05/C06 queda
`RemoteAcceptedNotDurable`. No existen retries remotos automáticos.

`Written`, `ExistingEquivalent` y `Replaced` son éxitos durables. `Replaced`
incluye una anomalía estructurada. Sólo un `Failure` incierto de persistencia
permite un `read()` de reconciliación y exige equivalencia C06 completa; nunca
repite POST, protección o persistencia.

La secuencia, máquina de fallos, cancelación, secretos, límites de zeroization y
ausencia de atomicidad distribuida se detallan en
[`docs/phase08/c07-enrollment-coordinator.md`](../../docs/phase08/c07-enrollment-coordinator.md).

## Capability Manifest C08

C08 expone un publicador invocable explícitamente. Lee el enrolamiento durable
C07, construye las 15 filas normativas en orden, usa
`Build.VERSION.RELEASE` sin normalizar y sólo consulta la presencia de
`PackageManager.FEATURE_WIFI`. No observa radio, asociación, SSID, BSSID, RSSI
ni conectividad.

El semantic fingerprint excluye únicamente ID, secuencia y `generated_at`. La
primera publicación reserva secuencia 0. Room v3 agrega una tabla singleton con
FK restrictiva al enrolamiento, accepted/pending all-or-none, payload canónico,
digests y fingerprints de 32 bytes. La reserva se confirma antes de Keystore o
red; timeout, respuesta incompleta, ack inválido o rechazo conservan pending
para un retry explícito byte-idéntico.

La publicación ejecuta un único `PUT` autenticado dentro del callback de
descifrado, sin redirects o retries automáticos. Sólo un ack 200 estricto mueve
pending a accepted. El mutex C08 es global de proceso pero independiente del
mutex C07; Room es la autoridad durable y cada transición revalida binding,
pending y credential activa.

C08 no agrega permisos ni componentes. Los IDs `nearby.wifi.devices` y
`vpn.consent` son conceptos publicados, no nombres Android universales, y se
marcan conservadoramente `permission_missing` sin inventar `denied`.

La matriz literal, transiciones de hardware, canonicalización, migración,
rollback, HTTP, seguridad y rebaseline C09–C14 están en
[`docs/phase08/c08-android-capability-manifest.md`](../../docs/phase08/c08-android-capability-manifest.md).

## Observación pasiva de conectividad y Wi-Fi C09

C09 separa la evidencia de red por defecto de la asociación Wi-Fi. El perfil
default `BASIC` observa transportes y capabilities sin pedir información
location-sensitive y redacta SSID/BSSID por policy. El perfil explícito
`WIFI_TEST_AUTHORIZED` intenta obtener esos identificadores únicamente con
manifest, grant runtime, ubicación y API compatibles; cualquier ausencia
degrada sólo los campos afectados con `null/reason`.

En API 31+ el mapper usa el `WifiInfo` entregado dentro de
`NetworkCapabilities` para la misma Network. En API 29–30 el fallback autorizado
de `WifiManager` queda marcado legacy, con confianza menor y sin afirmar red
default o path de tráfico. VPN y múltiples transportes se preservan.

Los snapshots en memoria incluyen UTC, `elapsedRealtimeNanos`, sequence local,
availability, source, confidence y reason. Pueden incluir RSSI, frecuencia,
banda/canal derivados, link rates, standard y security cuando Android los
expone; no presentan link speed como throughput ni inventan channel width o
MLO. No hay persistencia, DTO wire, publicación, upload o log de SSID/BSSID.

El manifest suma exactamente `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`,
`ACCESS_COARSE_LOCATION` y `ACCESS_FINE_LOCATION`; COARSE acompaña a FINE
porque Android 12/API 31+ exige declararlas y solicitarlas conjuntamente para
un futuro grant de ubicación precisa. `INTERNET` continúa llegando desde
`:core:data`.
No se declaran `NEARBY_WIFI_DEVICES`, `CHANGE_WIFI_STATE`, `neverForLocation` ni
permisos FGS. C09 no hace scan, conexión o administración Wi-Fi y no solicita
permisos mediante UI. `WIFI_TEST_AUTHORIZED` continúa exigiendo FINE realmente
concedido para intentar SSID/BSSID; COARSE por sí solo no es suficiente.
`BASIC` continúa operativo sin permisos peligrosos y no se suprime
`CoarseFineLocation`.

La matriz API/permisos, sentinels, lifecycle, privacidad, comparabilidad,
rollback y validación pendiente están en
[`docs/phase08/c09-android-connectivity-observation.md`](../../docs/phase08/c09-android-connectivity-observation.md).

## Generación verificada del Wrapper

El Wrapper fue generado con la distribución binaria oficial Gradle 8.13, sin
instalar Gradle globalmente. En PowerShell:

```powershell
$distributionSha256 = "20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78"
$archive = Join-Path $env:TEMP "gradle-8.13-bin.zip"
$distributionRoot = Join-Path $env:TEMP "wto-gradle-8.13"

Invoke-WebRequest -Uri "https://services.gradle.org/distributions/gradle-8.13-bin.zip" -OutFile $archive

if ((Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant() -ne $distributionSha256) {
    throw "Gradle 8.13 distribution checksum mismatch"
}

Expand-Archive -LiteralPath $archive -DestinationPath $distributionRoot
& (Join-Path $distributionRoot "gradle-8.13/bin/gradle.bat") --no-daemon --write-verification-metadata sha256 wrapper --gradle-version 8.13 --distribution-type bin --gradle-distribution-sha256-sum $distributionSha256
```

`gradle/wrapper/gradle-wrapper.properties` conserva el SHA-256 de la
distribución. El JAR generado se contrastó además con el checksum oficial del
Wrapper 8.13:
`81a82aaea5abcc8ff68b3dfcb58b3c3c429378efd98e7433460610fecd7ae45f`.

## Resolución reproducible

Los únicos repositorios permitidos son `google()` y `mavenCentral()`. Los
repositorios declarados por módulos fallan la configuración. El locking se
activa para todas las configuraciones resolubles de los subproyectos y los
lockfiles se generan únicamente al resolver tareas reales. Gradle verifica los
artefactos con los SHA-256 de `gradle/verification-metadata.xml` en modo estricto.

Comandos base desde este directorio:

```powershell
.\gradlew.bat --version
.\gradlew.bat projects
.\gradlew.bat tasks
.\gradlew.bat help
.\gradlew.bat :core:contracts:build :core:domain:build
.\gradlew.bat :core:domain:test
.\gradlew.bat :core:data:assembleDebug :core:platform:assembleDebug
.\gradlew.bat :app:assembleDebug lint
```

`local.properties`, `.gradle/`, `.kotlin/`, los directorios `build/` y los
paquetes APK/AAB son estado local ignorado y no forman parte del proyecto.
