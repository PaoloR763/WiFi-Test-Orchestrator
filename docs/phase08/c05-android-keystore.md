# C05 — protección de credentials con Android Keystore

## Estado y límite

C05 incorpora la base criptográfica Android para proteger una bearer credential
entregada por el backend. Android Keystore conserva una clave AES; no conserva
directamente la credential recuperable. El plaintext se cifra y descifra sólo
en memoria y C05 produce un envelope autenticado, cerrado y no serializable.

C05 no persiste el envelope, no modifica Room ni crea por sí sola estado de
enrolamiento durable. C07 compone el adapter lazy desde `:app`. C05 tampoco
agrega networking, retries, UI, WorkManager, Foreground Service, capabilities,
telemetría, tareas remotas ni operaciones públicas de delete, reset, export o
rotación. C06 persiste el envelope completo en Room v2 con identidad y metadata;
C07 coordina su producción y persistencia antes de afirmar enrolamiento durable.

El getter público `KeyInfo.isUnlockedDeviceRequired()` fue agregado recién en
Android 36.1. C05 distingue esa limitación conocida de un fallo de inspección:
en API 29–36.0 conserva evidencia `NOT_OBSERVABLE` y sólo acepta el alias fijo
v1 cuando todos los demás atributos observables son exactamente compatibles;
`NOT_REQUIRED` o `REQUIRED` son estados incoherentes para una plataforma que no
puede observar el getter y se rechazan.
La clave nueva siempre se genera explícitamente con
`setUnlockedDeviceRequired(false)`, pero esa solicitud no se presenta como
evidencia positiva después de reabrirla. Desde API 36.1 el seam productivo
invoca el getter exactamente una vez y debe observar `false`; `true` o evidencia
`NOT_OBSERVABLE` son incompatibles, mientras que cualquier excepción se propaga
para su clasificación cerrada como fallo del provider. El provider
AndroidKeyStore, `KeyInfo` auténtico y el comportamiento OEM reales siguen
pendientes de tests instrumentados C12.

## Arquitectura

La dependencia sigue siendo unidireccional:

```text
:core:platform -> :core:domain
```

- `:core:domain` permanece Kotlin/JVM puro. Contiene `CredentialProtector`, la
  policy v1, el envelope, AAD, resultados, errores y evidencia genérica de
  security level. No importa Android, Room, serialization ni tipos JCA.
- `:core:platform` contiene la factory lazy, el adapter Android Keystore, la
  validación de claves, AES-GCM, guards de thread, cleanup, clasificación de
  excepciones y seams `internal` para tests.
- El backend Android Keystore sólo abre el provider y devuelve `Missing`, una
  entrada no-`SecretKey`, o una `Candidate` formada por la clave y el descriptor
  estático observado en `KeyInfo`. No puede afirmar compatibilidad ni ejecutar
  la clasificación conductual final.
- `AndroidKeystoreKeyAccess` recibe cada candidatura y es el único dueño de la
  secuencia policy estática → probe randomized-IV → inspección compatible. El
  tipo de snapshot del backend no contiene ningún estado compatible,
  `probeVerified` ni evidencia prefabricada del probe.
- `:core:data` no implementa C05. C06 depende de sus tipos de domain y C07 llama
  al port sin conocer `KeyStore`, `SecretKey` o `Cipher`; data nunca depende de
  platform.
- `:app` no creó la factory ni generó claves en C05. C07 agrega composición
  lazy sin side effects eager.

La factory pública no recibe ni conserva `Context`, no abre Keystore y no hace
I/O. Cada invocación produce un adapter lazy con policy y alias v1 fijos.

## API pública

El port bloqueante expone:

```kotlin
interface CredentialProtector {
    fun inspect(): CredentialProtectionInspection
    fun prepare(): CredentialProtectionPreparation
    fun protect(credential: DeliveredCredential): ProtectCredentialResult
    fun useDecryptedCredential(
        envelope: ProtectedCredentialEnvelope,
        block: (AgentCredentialSecret) -> Unit,
    ): UseDecryptedCredentialResult
}
```

Todas las operaciones deben ejecutarse fuera del main thread. El callback de
descifrado devuelve exclusivamente `Unit`; capturar el secreto, su `String` o
bytes derivados fuera del callback viola el contrato. Una excepción del
callback se propaga sin convertirse en error criptográfico y sólo después del
cleanup.

La API no expone `Context`, aliases arbitrarios, `KeyStore`, `SecretKey`,
`Cipher`, excepciones Android/JCA, import/export, delete/reset ni grants entre
UIDs. Los resultados son jerarquías cerradas, no data classes, y sus
representaciones textuales están redactadas.

## Política criptográfica v1

| Propiedad | Valor |
| --- | --- |
| Algoritmo | AES |
| Tamaño de clave | 256 bits |
| Transformación | `AES/GCM/NoPadding` |
| Nonce | 12 bytes, generado por el provider |
| Authentication tag | 128 bits / 16 bytes |
| Plaintext | exactamente 89 bytes ASCII |
| Sealed credential | exactamente 105 bytes |
| Crypto version | `1` |
| Alias | `com.wifitestorchestrator.agent.credential.aead.v1` |
| Provider de clave | `AndroidKeyStore` |
| Provider de `Cipher` | selección JCA, sin fijarlo |
| StrongBox | no solicitado ni requerido |
| User authentication | `false` |
| User confirmation | `false` |
| Trusted user presence | `false` |
| Unlocked-device requirement | `false` |
| Usage count | sin límite |
| Validez temporal | ninguna |

`KeyGenParameterSpec` fija `PURPOSE_ENCRYPT | PURPOSE_DECRYPT`, 256 bits, GCM,
padding `NONE`, randomized encryption `true`, user authentication `false` y
unlocked-device requirement `false`. No configura StrongBox, attestation,
digests ni límites de uso. User confirmation y trusted user presence conservan
los defaults `false` del builder; la reapertura siempre inspecciona ambos
atributos y rechaza cualquier alias que los requiera.

Al cifrar se crea un `Cipher`, se llama `init(ENCRYPT_MODE, key)` sin IV y sin
`SecureRandom` provisto por el caller, luego se aplica AAD y `doFinal`. Sólo
después se lee el IV del provider y se exigen 12 y 105 bytes. Al descifrar se
crea otro `Cipher`, se usa `GCMParameterSpec(128, nonce)`, se aplica el mismo AAD
y se ejecuta `doFinal`. Nunca se comparte un `Cipher` entre threads.

Android documenta que, con randomized encryption requerida, un IV provisto por
el caller debe rechazarse durante encrypt. La inspección primero captura y
devuelve desde el backend una candidatura con todos los atributos estáticos
observables. `AndroidKeystoreKeyAccess` aplica la policy y sólo una candidatura
estáticamente compatible llega al probe conductual, porque `KeyInfo` no expone
el flag de randomized encryption. El backend no recibe el probe ni puede
construir el resultado final compatible. El probe intenta `Cipher.init()` con
un nonce GCM temporal de 12 bytes, sin ejecutar `doFinal()`: debe producir
`InvalidAlgorithmParameterException`; si el provider acepta el IV, la clave es
incompatible. Otros fallos no se interpretan como prueba positiva y se
clasifican de forma cerrada. Así, una colisión de alias sin `PURPOSE_ENCRYPT`,
con uso limitado u otra restricción observable retorna `KEY_INCOMPATIBLE` sin
llegar a `Cipher.getInstance()` ni `Cipher.init()`.

Referencias primarias:

- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder)
- [`KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo)
- [Diff de API 36.1 para `KeyInfo`](https://developer.android.com/sdk/api_diff/36.1/changes/android.security.keystore.KeyInfo)
- [`GCMParameterSpec`](https://developer.android.com/reference/javax/crypto/spec/GCMParameterSpec)

## Envelope v1 en memoria

`ProtectedCredentialEnvelope` contiene únicamente:

| Campo | Regla v1 |
| --- | --- |
| `cryptoVersion` | enum cerrado, sólo `1` |
| `keyAlias` | enum cerrado, sólo el alias v1 |
| `credentialId` | `CredentialId` válido |
| `credentialVersion` | `CredentialVersion` en `1..2147483647` |
| nonce | copia privada de exactamente 12 bytes |
| sealed credential | copia privada de exactamente 105 bytes |

El constructor es privado y la factory falla cerrado ante versión, alias o
tamaños desconocidos. Los arrays se copian al entrar y sólo se entregan como
copias temporales dentro de callbacks que se limpian al terminar. La clase no
es data class ni `Serializable`, no tiene anotaciones de serialización y
conserva igualdad y hashing referenciales. `toString()` no incluye versión,
alias, IDs, nonce ni ciphertext.

C05 no define formato de disco, DTO, JSON, columnas ni tabla Room. C06 define
una serialización explícita sin reinterpretar jamás v1.

## AAD v1

El AAD autentica propósito, crypto version, alias, credential ID y credential
version. No incorpora installation ID, URL del servidor, backend agent ID,
schema HTTP, issued/expires, delivery state, paths ni valores opcionales.

| Offset | Tamaño | Contenido |
| --- | ---: | --- |
| `0..27` | 28 | ASCII `WTO_ANDROID_AGENT_CREDENTIAL` |
| `28..31` | 4 | crypto version Int32 big-endian, `1` |
| `32..33` | 2 | longitud alias UInt16 big-endian, `49` |
| `34..82` | 49 | alias ASCII v1 |
| `83..98` | 16 | UUID: MSB seguido de LSB, big-endian |
| `99..102` | 4 | credential version Int32 big-endian |

El total es exactamente 103 bytes. El golden vector usa credential ID
`10000000-0000-4000-8000-000000000001` y credential version `1`:

```text
57544f5f414e44524f49445f4147454e545f43524544454e5449414c000000010031636f6d2e77696669746573746f7263686573747261746f722e6167656e742e63726564656e7469616c2e616561642e76311000000000004000800000000000000100000001
```

Una evolución requiere nueva crypto version y nuevo alias. V1 nunca cambia de
significado.

## Lifecycle, idempotencia y concurrencia

- `inspect()` sólo relee y valida; nunca crea.
- `prepare()` crea si falta, relee siempre y devuelve `Created` o
  `AlreadyCompatible`. Una carrera que informa fallo de creación puede ser
  éxito si la relectura encuentra la clave compatible ganadora.
- `protect()` revalida y puede crear idempotentemente si falta. Una clave
  incompatible falla cerrado.
- `useDecryptedCredential()` valida el envelope antes de consultar la clave y
  nunca crea si falta.

Un único lock productivo por alias v1 se comparte entre todas las instancias
del adapter dentro del proceso. Sólo cubre load/inspect/create/reinspect; no se
mantiene durante encrypt, decrypt ni callback. Después de crear se relee una
vez, sin retry loop. Una clave incompatible, invalidada o desconocida no se
borra ni reemplaza. No existen procesos Android secundarios en este corte.

La validación exige una entrada `SecretKey`, algoritmo AES, `encoded == null`,
`format == null`, 256 bits, purposes exactos, sólo GCM, sólo `NoPadding`,
user authentication `false`, user confirmation `false`, trusted user presence
`false`, ausencia de fechas, alias exacto, origen `GENERATED` y contador de uso
sin límite cuando es observable. Sólo después demuestra conductualmente
randomized encryption. Desde API 36.1 exige además observar unlocked-device
requirement `false`. En API 29–36.0 acepta exclusivamente la limitación conocida
`NOT_OBSERVABLE`; una evidencia positiva fabricada no es válida y no se relaja
ninguno de los demás atributos.
El security level se informa como evidencia genérica y no bloquea
compatibilidad: software, hardware legacy sin nivel preciso, TEE, StrongBox,
unknown-secure o unknown.

### Compatibilidad API

| Runtime | Evidencia disponible | Resultado de la policy estricta |
| --- | --- | --- |
| API 29–30 | `isInsideSecureHardware`; sin getters de usage count ni unlocked-device | usage count y unlocked-device quedan `NOT_OBSERVABLE`; no se inventa un valor |
| API 31–32 | security level y usage count observables; sin getter unlocked-device | usage count debe ser exactamente `UNRESTRICTED_USAGE_COUNT`; unlocked-device conserva la regla acotada pre-36.1 |
| API 33–36.0 | errores Keystore estructurados; sin getter unlocked-device | misma regla acotada pre-36.1 |
| API 36.1+ | getter unlocked-device público | requiere evidencia observada `NOT_REQUIRED`; sin fallback pre-36.1 |

La matriz de coherencia entre runtime y evidencia es cerrada:

| Runtime | `NOT_OBSERVABLE` | `NOT_REQUIRED` | `REQUIRED` |
| --- | --- | --- | --- |
| API 29–36.0 | puede continuar si todo lo demás es exacto | incompatible: estado imposible | incompatible |
| API 36.1+ | incompatible: no oculta fallos | puede continuar si todo lo demás es exacto | incompatible |

`KeyInfo.getRemainingUsageCount()` y `setMaxUsageCount()` existen desde API 31.
En API 29–30 el getter no se invoca y la única evidencia coherente es
`NOT_OBSERVABLE`. Desde API 31 el getter se invoca una vez y sólo
`KeyProperties.UNRESTRICTED_USAGE_COUNT` es compatible; `0`, `1`, `2` o
cualquier otro límite son incompatibles antes del probe. Una clave limited-use
nunca puede producir un envelope ni se borra o reemplaza automáticamente.

Los parámetros de duración de autenticación, validez on-body, invalidación por
enrolamiento biométrico y enforcement de autenticación por hardware quedan
inertes porque la invariante primaria exige
`userAuthenticationRequired == false`. No se reinterpretan como evidencia
independiente. Security level sigue siendo informativo y su comportamiento real
por provider/OEM se valida en C12.

La creación usa la policy exacta en todos los API soportados. Para un alias
preexistente en API 29–36.0 la aplicación no puede demostrar individualmente el
atributo unlocked-device: sólo puede aceptarlo bajo el alias fijo/versionado,
origen `GENERATED`, no exportabilidad observable y el conjunto completo de
atributos y comprobaciones conductuales exigidos. Esto es una limitación de
observabilidad, no prueba positiva de `false`. Cualquier incompatibilidad
observable o excepción de provider sigue fallando cerrado; no se borra,
reemplaza ni regenera el alias. No se usa reflection de APIs ocultas.

## Plaintext, secretos y cleanup

Al cifrar, `DeliveredCredential.useSecret` acota el raw. C05 exige longitud 89,
convierte carácter por carácter a ASCII sin replacement y limpia el array en
`finally`. Al descifrar exige 89 bytes, rechaza cualquier byte no ASCII,
construye el `String` necesario, ejecuta `AgentCredentialSecret.parse()`,
comprueba que su credential ID coincida con el autenticado por envelope/AAD y
recién entonces llama al consumidor.

Se limpian best-effort plaintext, decrypted bytes, AAD y buffers intermedios de
nonce/ciphertext que ya fueron copiados al envelope. El nonce y sealed
credential retenidos por el envelope no se limpian porque son necesarios para
uso posterior, pero nunca se imprimen. JVM/Kotlin/JCA pueden generar `String` y
copias internas que no pueden zeroizarse con garantía ni de inmediato; C05 no
afirma lo contrario. Heap dumps de producción deben tratarse como material
sensible.

No se registran credential, token, plaintext, ciphertext, nonce, alias,
headers, bodies, paths, mensajes de provider, cause ni stack interno. Tests y
fixtures usan secretos sintéticos y no los interpolan en mensajes de error.
Compose previews, recursos, screenshots y clipboard están fuera de alcance y
no deben introducir secretos en bloques posteriores.

## Errores, cancelación y cleanup

Los únicos errores públicos son:

`KEY_MISSING`, `KEY_INCOMPATIBLE`, `KEY_INVALIDATED`,
`KEY_PERMANENTLY_INVALIDATED`, `KEYSTORE_TEMPORARILY_UNAVAILABLE`,
`DEVICE_LOCKED`, `PROVIDER_FAILURE`, `MALFORMED_ENVELOPE`, `INVALID_NONCE`,
`UNSUPPORTED_CRYPTO_VERSION`, `UNKNOWN_KEY_ALIAS`, `AUTHENTICATION_FAILED`,
`ENCRYPTION_FAILED` y `DECRYPTION_FAILED`.

Mapeo interno principal:

| Evidencia interna | Error público |
| --- | --- |
| alias ausente en decrypt | `KEY_MISSING` |
| atributo observable incompatible o evidencia unlocked-device inválida para el runtime | `KEY_INCOMPATIBLE` |
| fallo inesperado al obtener `KeyInfo` o leer el getter disponible | `PROVIDER_FAILURE` o categoría Keystore específica |
| `KeyPermanentlyInvalidatedException` | `KEY_PERMANENTLY_INVALIDATED` |
| key expired/not-yet-valid, unrecoverable o invalid key | `KEY_INVALIDATED` |
| `BackendBusyException` o `KeyStoreException` transitoria | `KEYSTORE_TEMPORARILY_UNAVAILABLE` |
| autenticación requerida/device locked | `DEVICE_LOCKED` |
| `AEADBadTagException` durante decrypt | `AUTHENTICATION_FAILED` |
| nonce generado con tamaño distinto | `INVALID_NONCE` |
| fallo no clasificado de Keystore/JCA | `PROVIDER_FAILURE`, `ENCRYPTION_FAILED` o `DECRYPTION_FAILED` según operación |

`AUTHENTICATION_FAILED` no distingue ciphertext, tag, AAD, nonce o clave
incorrecta. Un plaintext autenticado pero inválido usa `DECRYPTION_FAILED` sin
revelar longitud, carácter, segmento o ID divergente. Los resultados no
conservan excepciones ni mensajes originales.

Antes de mapear cualquier `Exception`, la cadena de causes se recorre por
identidad, se detiene ante ciclos y relanza exactamente la primera
`CancellationException`. Las subclases de `Error` nunca se convierten. Si una
operación primaria y su cleanup fallan, se conserva la primaria y se agrega el
cleanup como suppressed, evitando self-suppression; si sólo falla cleanup, ese
fallo se propaga.

El acceso desde main thread produce `IllegalStateException` como error de
programación, antes de I/O, y no una categoría criptográfica durable. C06 será
responsable del dispatcher.

## Threat model y backup

C05 reduce el impacto de copiar archivos privados, leer accidentalmente un
schema futuro o restaurar un envelope sin la clave: el plaintext no está en el
envelope y las claves Android Keystore no forman parte del backup de datos de
la app. GCM y AAD detectan cambios de ciphertext, tag, nonce y contexto. La
redacción reduce exposición accidental por logs, excepciones y crash reports.

No ofrece protección absoluta frente a un dispositivo desbloqueado con el
proceso comprometido, root, hooking/instrumentación, código con el mismo UID o
lectura de memoria mientras el secreto se usa. Tampoco garantiza borrado de
todas las copias JVM. Screenshots y clipboard no aplican porque C05 no tiene
UI.

Un uninstall/reinstall elimina normalmente la entrada Keystore de la app; un
envelope restaurado o conservado sin clave debe fallar `KEY_MISSING`. C06
persistirá bajo la política no-backup ya establecida y debe tratar esa
combinación como estado no recuperable automáticamente. Un rollback puede dejar
una clave v1 huérfana; ninguna versión debe borrarla en forma automática. Un
envelope de versión futura falla cerrado en una app anterior.

C05 agrega cero permisos, Activity, Service, Receiver, Provider, launcher,
`android:process`, cleartext o network security config. No modifica manifests
ni XML de backup.

## Dependencias y evidencia host

Producción usa sólo framework Android y JCA. No agrega Jetpack Security Crypto,
EncryptedSharedPreferences, SQLCipher, Android KeyChain, BouncyCastle,
Conscrypt ni repositorios. Robolectric 4.16.1 y kotlin-test/JUnit ya estaban
versionados por C04 y se reutilizan sólo en tests. Las dependencias
BouncyCastle/Conscrypt transitivas de Robolectric no son providers productivos.

Los tests JVM puros cubren policy, modelos, validación, copias defensivas,
igualdad referencial, redacción, AAD completo, endianess y límites de versión.
Los tests de `:core:platform` cubren JCA host AES-GCM, tamaños, tampering, key/AAD
incorrectos, parsing ASCII, ID mismatch, cleanup, cancellation, causes cíclicas,
`Error`, un `Cipher` por operación, lifecycle, carreras, lock compartido,
guard de main thread, factory lazy, policy observable y manifest fuente. Seams
productivos internos deciden, con la versión de plataforma, si pueden invocar
los getters de unlocked-device y usage count y transforman sus resultados en
evidencia. Las regresiones host usan esas mismas funciones para comprobar los
boundaries, cantidad de invocaciones y propagación de fallos. Un backend host
sintético entrega únicamente `Candidate`; los tests recorren el mismo ownership
productivo `Candidate` → `AndroidKeystoreKeyAccess` → policy estática → probe →
lifecycle y comprueban que no existe un snapshot compatible construible por el
backend. También prueban que cada atributo estático incompatible omite el probe
y que confirmation, trusted presence y usage limitado devuelven
`KEY_INCOMPATIBLE`. No construyen ni atraviesan un `KeyInfo` auténtico.

Robolectric valida la construcción de `KeyGenParameterSpec` y seams Android,
pero no demuestra provider `AndroidKeyStore`, KeyMint, no exportabilidad real,
hardware/TEE/StrongBox, persistencia entre procesos, invalidación OEM, reboot,
uninstall ni restore.

## Integración implementada por C06/C07

C06 persiste en Room v2, de forma atómica con identidad y metadata:

- sealed credential de 105 bytes;
- nonce de 12 bytes;
- alias real v1;
- crypto version `1`;
- credential ID y credential version autenticados;
- identidad backend y metadata de enrolamiento requeridas por su contrato.

No persiste plaintext ni usa cero, vacío o placeholders para ausencia. C07
ejecuta el preflight C06 antes de tocar Keystore: usa `prepare()` sólo ante
estado durable `Absent` y `inspect()` sólo ante `Compatible`. Retry remoto
automático, recovery y reset continúan excluidos.

## Diferido a C12 — NOT RUN

No se ejecutaron emuladores ni dispositivos en C05. Quedan explícitamente
`NOT RUN`:

- provider `AndroidKeyStore` real en API 29 y API 36/36.1;
- `encoded == null`, confirmation/presence, usage count y policy `KeyInfo` real;
- generación, reapertura y restart de proceso;
- encrypt/decrypt y unicidad de nonce reales;
- ciphertext/tag/AAD/nonce alterados en KeyMint;
- alias incompatible y carrera entre instancias reales;
- lock screen, invalidación y disponibilidad tras boot;
- StrongBox presente/ausente sin convertirlo en requisito;
- TEE/software y diferencias OEM;
- uninstall/reinstall y restore sin clave cuando sean automatizables;
- confirmación de cero permisos y componentes en manifests instalados.

Hasta esa evidencia no se afirma hardware-backed, StrongBox, no exportabilidad
real en dispositivo ni compatibilidad operacional de Android Keystore.
