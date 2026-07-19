# Android agent

Este directorio contiene exclusivamente el bootstrap reproducible C01 del
agente Android. El proyecto no define todavía pantallas, actividades, servicios,
permisos, persistencia, red, contratos de aplicación ni capabilities.

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
- `:core:contracts`: módulo Kotlin/JVM puro.
- `:core:domain`: módulo Kotlin/JVM puro, sin dependencia de Android.
- `:core:data`: biblioteca Android; depende de domain y contracts.
- `:core:platform`: biblioteca Android; depende de domain.

Los módulos están vacíos de comportamiento intencionalmente. La inyección de
dependencias será manual cuando una fase funcional la requiera.

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
.\gradlew.bat :core:data:assembleDebug :core:platform:assembleDebug
.\gradlew.bat :app:assembleDebug lint
```

`local.properties`, `.gradle/`, `.kotlin/`, los directorios `build/` y los
paquetes APK/AAB son estado local ignorado y no forman parte del proyecto.
