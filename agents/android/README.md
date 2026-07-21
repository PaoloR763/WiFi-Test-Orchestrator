# Android agent

Este directorio contiene el bootstrap reproducible C01, los contratos wire de
enrolamiento C02A y el dominio base puro C02B del agente Android. El proyecto no
define todavía pantallas, actividades, servicios, permisos, persistencia, red,
mapping DTO/dominio ni capabilities.

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
- `:core:contracts`: módulo Kotlin/JVM puro con los DTOs públicos de
  enrolamiento C02A.
- `:core:domain`: módulo Kotlin/JVM puro con identidad, configuración segura,
  secretos, credenciales y aceptación factual de enrolamiento C02B.
- `:core:data`: biblioteca Android; depende de domain y contracts.
- `:core:platform`: biblioteca Android; depende de domain.

Los módulos `data` y `platform` permanecen vacíos de comportamiento
intencionalmente. La inyección de dependencias será manual cuando una fase
funcional la requiera.

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

C02A no implementa dominio, mapping DTO/domain, cliente HTTP, persistencia,
Keystore, enrolamiento ejecutable, UI ni tareas remotas. El dominio puro se
incorpora por separado en C02B; mapping y transporte permanecen diferidos a C03.

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
backend no convierte por sí sola al agente en `Enrolled`: C02B no tiene mapper,
HTTP, retry, Room, DataStore, SharedPreferences, Android Keystore, UI,
WorkManager, Foreground Service ni tareas remotas.

El regex SemVer publicado en `shared/contracts` admite algunas formas de
prerelease que SemVer 2.0 estricto rechaza, como identificadores vacíos o
numéricos con ceros iniciales. Los contratos normativos no se cambian en C02B;
C03 deberá reportar esa diferencia como violación contractual explícita y nunca
normalizarla silenciosamente.

Los tests de C02B son JVM puros. Tests instrumentados y emuladores no aplican y
no se ejecutan en este corte.

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
