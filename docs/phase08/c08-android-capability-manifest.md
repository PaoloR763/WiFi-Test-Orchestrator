# C08 — Capability Manifest Android

## Alcance cerrado

C08 construye un snapshot determinista, reserva una secuencia monotónica,
persiste `pending` antes de Keystore/red y publica el payload canónico mediante
un `PUT` HTTPS autenticado. El use case es explícito: no se invoca desde
constructores, `Application.onCreate`, enrolamiento, startup ni lifecycle.

El bloque no observa SSID/BSSID/RSSI/conectividad, no hace scans, no declara
permisos, no agrega componentes Android y no implementa WorkManager, UI,
Foreground Service, tareas remotas, probes, tráfico, throughput, captura o
replay.

## Rebaseline restante

- C08: Capability Manifest, congelamiento, Room v3 y publicación idempotente.
- C09: observación pasiva de conectividad y Wi-Fi.
- C10: WorkManager y mobile presence.
- C11: UI y experiencia operativa. Un Foreground Service sólo será admisible
  para una operación concreta, prolongada, visible, iniciada por el usuario y
  permitida por Android; WorkManager o mantener vivo el proceso no lo
  justifican.
- C12: instrumentación real, API 29/35/36/36.1, Keystore/KeyMint, hardware,
  restart y process death.
- C13: CI Android.
- C14: documentación, aceptación y cierre.

Las tareas remotas siguen en la Fase 10 global y probes/tráfico en la Fase 11.

## Matriz nominal exacta

Todas las filas tienen `version=1.0.0`. La notación es
`status/reason`; `—` representa `reason=null`. `perm` agrega la lista de
identificadores conceptuales; `provider` agrega `implementations=[]`. En todas
las filas los cinco límites numéricos son `null`.

| id | technical_support | implementation_status | permission_requirement | user_interaction | background_execution | provider | limitations |
|---|---|---|---|---|---|---|---|
| `wifi.connection.read` | `conditional/—` | `planned/not_implemented` | `required/[nearby.wifi.devices]/permission_missing` | `conditional/user_interaction_required` | `bounded/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `wifi.scan` | `conditional/—` | `planned/not_implemented` | `required/[nearby.wifi.devices]/permission_missing` | `conditional/user_interaction_required` | `bounded/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `wifi.rssi.read` | `conditional/—` | `planned/not_implemented` | `required/[nearby.wifi.devices]/permission_missing` | `conditional/user_interaction_required` | `bounded/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `network.icmp.ping` | `unknown/unknown` | `planned/not_implemented` | `unknown/[]/unknown` | `none/—` | `bounded/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `network.tcp.probe` | `supported/—` | `planned/not_implemented` | `none/[]/—` | `none/—` | `bounded/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `network.http.probe` | `supported/—` | `planned/not_implemented` | `none/[]/—` | `none/—` | `bounded/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `traffic.tcp.throughput` | `conditional/—` | `planned/not_implemented` | `none/[]/—` | `required/user_interaction_required` | `foreground_only/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `traffic.udp.throughput` | `conditional/—` | `planned/not_implemented` | `none/[]/—` | `required/user_interaction_required` | `foreground_only/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `traffic.http.download` | `supported/—` | `planned/not_implemented` | `none/[]/—` | `conditional/user_interaction_required` | `bounded/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `traffic.http.upload` | `supported/—` | `planned/not_implemented` | `none/[]/—` | `conditional/user_interaction_required` | `bounded/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `traffic.latency_under_load` | `conditional/—` | `planned/not_implemented` | `none/[]/—` | `required/user_interaction_required` | `foreground_only/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `capture.ip` | `conditional/—` | `not_implemented/not_implemented` | `required/[vpn.consent]/permission_missing` | `required/user_interaction_required` | `foreground_only/lifecycle_restricted` | `unavailable/[]/provider_unavailable` | `unknown/(todos null)/unknown` |
| `capture.ieee80211.monitor` | `unsupported/not_exposed_by_platform` | `excluded/not_applicable` | `not_applicable/[]/not_applicable` | `not_applicable/not_applicable` | `not_applicable/not_applicable` | `not_applicable/[]/not_applicable` | `not_applicable/(todos null)/not_applicable` |
| `traffic.pcap.replay` | `unsupported/not_applicable` | `excluded/not_applicable` | `not_applicable/[]/not_applicable` | `not_applicable/not_applicable` | `not_applicable/not_applicable` | `not_applicable/[]/not_applicable` | `not_applicable/(todos null)/not_applicable` |
| `execution.background.continuous` | `unsupported/lifecycle_restricted` | `excluded/not_applicable` | `not_applicable/[]/not_applicable` | `not_applicable/not_applicable` | `not_supported/lifecycle_restricted` | `not_applicable/[]/not_applicable` | `not_applicable/(todos null)/not_applicable` |

OkHttp sólo transporta enrolamiento y el manifest. No convierte HTTP probes o
tráfico en funcionalidad implementada ni en un provider disponible.

### Transición de hardware Wi-Fi

`PackageManager.FEATURE_WIFI=true` conserva las tres filas nominales. Con
`false`, cada fila Wi-Fi produce:

- `technical_support=unsupported/not_exposed_by_platform`;
- `implementation_status=planned/not_implemented`;
- permiso, interacción, background y limitations
  `not_applicable/.../not_applicable`;
- `provider=unavailable/[]/provider_unavailable`.

Una excepción o resultado ambiguo produce sólo
`technical_support=unknown/unknown`; las otras seis dimensiones conservan el
fallback nominal fail-closed. El estado del radio, asociación y conectividad es
C09.

## Plataforma y permisos

`platform_version` es exactamente `Build.VERSION.RELEASE`, opaco, sin trim,
parseo, normalización ni sustitución. Debe contener entre 1 y 64 code points y
no puede tener surrogates inválidos. Un valor inválido bloquea antes de
persistir o publicar. `SDK_INT`/`SDK_INT_FULL` no se publican.

`nearby.wifi.devices` y `vpn.consent` son conceptos del producto, no nombres
literales de permisos Android para todas las APIs. Como C08 no declara ni
solicita permisos, publica `required/permission_missing`, nunca `denied` ni
`restricted`: no existe evidencia de una decisión del usuario. En API
29/35/36.0/36.1 el manifest y la política son iguales; la traducción a permisos
Android concretos y su concesión pertenece a C09/C11/C12.

C08 no agrega `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE`,
`ACCESS_FINE_LOCATION`, `NEARBY_WIFI_DEVICES`, `POST_NOTIFICATIONS`, permisos
FGS/VPN ni componentes.

## Canonicalización, fingerprint y secuencia

El JSON canónico usa UTF-8, claves de objeto ordenadas, arrays en orden, sin
whitespace insignificante, BOM, NaN, Infinity o números no enteros. Los escapes
son deterministas. El entero `-0` se canoniza como `0`: por lo tanto, bytes
persistidos que contengan `-0` no son canónicos y se clasifican como corruptos,
aun cuando su digest y fingerprint almacenados coincidan. El digest es SHA-256
del payload completo.

El semantic fingerprint es SHA-256 del JSON canónico con
`schema_version`, `agent_id`, `agent_version`, `platform`,
`platform_version`, `protocol_version`, `capability_catalog_version` y las 15
capabilities. Excluye sólo `manifest_id`, `manifest_sequence` y `generated_at`.

La primera secuencia es 0. Cada snapshot nuevo usa la anterior más uno. Un
pending bloquea otra reserva y conserva ID, secuencia, timestamp, payload,
digest y fingerprint en retries; nonce, timestamp HTTP y correlation ID se
renuevan por intento. `Long.MAX_VALUE` es el máximo: el mismo fingerprint
accepted devuelve `AlreadyCurrent`; uno diferente devuelve
`SequenceExhausted` antes de UUID, manifest clock, Keystore o red.

### Validación nueva e histórica

La construcción de un snapshot nuevo y la rehidratación de uno persistido
aplican políticas distintas de forma deliberada:

- `semanticFingerprint()` y `freeze()` exigen igualdad exacta con el
  `AndroidCapabilityCatalog` de la aplicación instalada. Un caller no puede
  congelar ni publicar una matriz arbitraria.
- `reserve()` vuelve a validar de forma independiente identidad, secuencia,
  UUID v4, timestamp, canonicalidad, digest, fingerprint y la matriz exacta del
  catálogo actual antes de escribir una reserva nueva. El constructor de
  `FrozenCapabilityManifest` y la rehidratación histórica son internos al
  módulo; la frontera pública no convierte bytes arbitrarios en candidatos
  reservables.
- accepted y pending ya persistidos se validan mediante un dispatch explícito
  por `schema_version` y `capability_catalog_version`. El perfil inmutable
  schema/catalog 1.0.0 reproduce el contrato normativo 1.0.0 —estructura
  cerrada, 15 IDs, siete dimensiones, enums, reasons, permisos, providers y
  límites— sin reconstruir el catálogo Android actual ni depender de sus enums
  reducidos. Una combinación de versiones desconocida falla cerrada.

Un snapshot histórico contractualmente válido conserva sin regeneración su
payload, digest y semantic fingerprint originales aunque una actualización
haya cambiado status, provider, reason o limitations del catálogo instalado.
La misma validación se usa al rehidratar tanto accepted como pending. La
invariante Android exige UUID v4 canónico en ambos casos, aunque el tipo UUID
genérico del schema admita versiones 1–8.

El timestamp histórico del perfil 1.0.0 acepta `T` o `t` como separador,
mantiene `Z` mayúscula y los límites normativos de calendario, longitud y
precisión fraccionaria. La conversión temporal nunca reserializa el documento:
un payload histórico con `t` minúscula se conserva byte por byte.

Los opcionales `reason.detail` y los cinco límites numéricos sólo admiten
omisión o un valor de su tipo y rango contractual. Su presencia con `null` se
rechaza inspeccionando el `JsonObject` original. Esto no cambia los campos
`reason` requeridos de cada dimensión, que sí admiten explícitamente `null`.

## Room v3 y recuperación

La migración 2→3 agrega únicamente
`capability_manifest_publication`, singleton con FK a
`protected_enrollment(singleton_id)`, `ON DELETE RESTRICT` y `ON UPDATE NO
ACTION`. Accepted y pending son tuplas all-or-none. Digests/fingerprints son
BLOB de 32 bytes, UUID texto canónico de 36, payload 1..262144 bytes,
nanoseconds 0..999999999 y flags INTEGER 0/1.

Los schemas 1 y 2 se preservan byte-idénticos. V1 abre por 1→2→3, v2 por 2→3,
v3 directamente y fresh v3 instala los mismos guards mediante una única fuente
SQL. No hay backfill, migración destructiva, downgrade ni unenrollment.

Antes de getters coercivos, la lectura valida `typeof`, longitudes con `CASE` y
`Cursor.getType`; un BLOB sobredimensionado no se materializa. Luego revalida
UUID, timestamps, JSON canónico, digest, fingerprint, binding y el perfil
histórico versionado del contrato. Toda ambigüedad es `Corrupt`.

Un pending se escribe antes de Keystore/red y sobrevive timeout, I/O, ack
inválido, rechazo y process death. Un ack sólo mueve pending a accepted dentro
de una transacción que revalida binding, pending y credential usada. Volver a
un APK v2 después de abrir una DB real v3 falla de forma segura; el rollback
operativo no debe borrar la base real.

La regresión durable de C08 inserta un pending histórico contractualmente
válido pero distinto del catálogo actual, cierra por completo la base
file-backed, reabre el mismo archivo, verifica preflight y rehidratación exacta,
publica los mismos bytes, confirma el ack y vuelve a reabrir para recuperar el
accepted sin reconstruir la matriz instalada.

## Seguridad, concurrencia y HTTP

Todas las instancias productivas C08 comparten un mutex de proceso propio; no
comparte ni modifica el mutex C07. Room sigue siendo la autoridad durable.
Cada reserva y commit revalida la identidad/servidor mediante un binding
SHA-256 versionado que excluye credential ID/version, por lo que una rotación
válida del mismo agente permite retry, pero nunca confirma bajo metadata de
credential distinta de la usada.

La credential plaintext sólo existe dentro de
`CredentialProtector.useDecryptedCredential`; el `Call` se crea, ejecuta,
cancela y libera dentro del callback, sobre dispatcher I/O. La cancelación
adelante `Call.cancel()` una vez; un ack ya validado se confirma en
`NonCancellable` y después se propaga la cancelación. El Throwable primario se
preserva y cleanup diferente se agrega como suppressed.

El request es `PUT /api/v1/agents/self/capability-manifest`, body pending exacto,
Bearer, timestamp UTC, nonce aleatorio de 16 bytes base64url sin padding,
protocolo 1.0.0 y correlation ID fresco. No usa `Idempotency-Key`, redirects,
retry automático, cookies, cache, authenticator ni trust-all.

Sólo se acepta 200 con un único correlation ID idéntico, MIME JSON permitido,
body ≤65536, JSON sin duplicados/desconocidos, schema 1.0.0, manifest ID y
digest idénticos y timestamp UTC válido. Nunca se exponen Authorization,
payloads o bodies arbitrarios en logs, resultados, errores o `toString()`.

## Evidencia y límites

Tests JVM congelan DTOs, orden, 15 filas, hardware true/false/unknown,
canonicalización, fingerprints y overflow. Robolectric/SQLite ejercita fresh
v3, v1→2→3, v2→3, reopen, FK, guards, storage classes adversariales,
concurrencia, retry/process recreation, HTTP y composición lazy.

Robolectric no constituye ejecución real en API 35, 36 o 36.1. Emuladores API
29/35/36/36.1, dispositivo físico, Keystore/KeyMint, reboot, process death real,
OEM y hardware Wi-Fi quedan para C12. CI queda para C13 y la aceptación integral
para C14.
