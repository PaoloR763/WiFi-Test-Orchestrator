# C04 — base de persistencia Android con Room

## Alcance

C04 incorpora una base Room mínima para el estado local no sensible del agente
Android. Persiste exclusivamente:

- la identidad canónica de la instalación local;
- la configuración HTTPS canónica del servidor actual;
- los timestamps locales de creación y actualización asociados.

No persiste identidad asignada por el backend, estado de enrolamiento,
credential metadata, tokens, credentials, request/response bodies, errores del
backend, mensajes, details, excepciones ni blobs genéricos. La API pública de
persistencia sólo acepta modelos puros de `:core:domain` que no contienen
secretos.

Room, Android `Context`, entities, DAO, `RoomDatabase` y SQLite quedan
confinados a `:core:data`. `:core:contracts` y `:core:domain` permanecen JVM
puros y sin cambios.

## Inicialización y ubicación

`AndroidLocalPersistenceFactory` captura inmediatamente `applicationContext`,
pero crear la factory o pedir el repositorio no construye ni abre la base. La
primera operación obtiene de `ProcessRoomDatabaseProvider` una única instancia
por proceso y recién entonces construye Room. La apertura y el I/O continúan
siendo lazy.

La base se llama `wto-agent.db`. El helper AndroidX usa explícitamente
`SupportSQLiteOpenHelper.Configuration.noBackupDirectory(true)` y garantiza el
directorio al comenzar el primer acceso. No se pasa un path absoluto como
nombre de base ni se depende de una interpretación accidental del nombre. El
archivo principal queda bajo `applicationContext.noBackupFilesDir`, no bajo el
directorio estándar de databases.

No se habilitan consultas en el main thread, auto-close, multi-instance
invalidation ni procesos Android secundarios. El cierre no forma parte de la
API de consumo; existe únicamente un cierre `internal` para tests o
mantenimiento controlado.

## Schema Room v1

La clase es
`com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase`, usa
versión `1`, `exportSchema = true` y journal mode
`WRITE_AHEAD_LOGGING`. El schema generado por Room/KSP se versiona en:

`agents/android/core/data/schemas/com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase/1.json`

Su identity hash es `2a33bf103f9927f13a8246f20d09ad8e`.

### `local_installation`

| Columna | Tipo SQLite | Null | Regla |
| --- | --- | --- | --- |
| `singleton_id` | `INTEGER` | no | primary key; el repositorio sólo acepta `1` |
| `installation_id` | `TEXT` | no | índice unique; UUID canónico validado por dominio |
| `created_at_epoch_seconds` | `INTEGER` | no | segundos UTC de `Instant` |
| `created_at_nanoseconds` | `INTEGER` | no | nanos `0..999999999`, validados al mapear |

La cardinalidad efectiva es `0..1`. Un `singleton_id` distinto de `1`, más de
una fila efectiva, un UUID no canónico o un timestamp inválido hacen fallar la
lectura de forma cerrada. Una candidata igual es idempotente; una distinta
produce conflicto y nunca reemplaza al ganador.

### `server_configuration`

| Columna | Tipo SQLite | Null | Regla |
| --- | --- | --- | --- |
| `singleton_id` | `INTEGER` | no | primary key y foreign key a la instalación |
| `base_url` | `TEXT` | no | `ServerBaseUrl` HTTPS canónica, revalidada al leer |
| `updated_at_epoch_seconds` | `INTEGER` | no | segundos UTC de `Instant` |
| `updated_at_nanoseconds` | `INTEGER` | no | nanos `0..999999999`, validados al mapear |

La foreign key referencia
`local_installation(singleton_id)` con `ON DELETE RESTRICT` y
`ON UPDATE NO ACTION`. Por eso no puede existir configuración sin instalación
mediante la API ni mediante una escritura SQLite válida con foreign keys
activas. Su cardinalidad efectiva también es `0..1`.

No existen otras tablas o columnas. Las entities guardan primitivas; no hay
`TypeConverter`. `Instant` se representa como el par `(epoch seconds,
nanoseconds)`, que conserva valores pre-epoch y precisión nanosegundo sin
timezone ni overflow de epoch-nanos. No se usa cero como sentinel: la ausencia
de una fila representa ausencia de estado.

## API y atomicidad

`LocalStateRepository` está en `data.persistence`; no filtra tipos Android o
Room. Expone cuatro operaciones suspendidas:

- `readLocalState`: snapshot transaccional de ambas tablas. Devuelve `Absent`,
  `InstallationOnly`, `Configured` o `Failure`.
- `ensureLocalInstallation`: devuelve `Created`, `Existing`, `Conflict` o
  `Failure`. El insert usa `IGNORE` sólo para resolver la carrera y relee al
  ganador; nunca usa `REPLACE` o `@Upsert`.
- `initializeLocalState`: crea instalación y configuración dentro de una única
  transacción. Devuelve `Created`, `ExistingEquivalent`, `Conflict` o
  `Failure`.
- `setServerConfiguration`: exige instalación y devuelve `Created`, `Updated`,
  `Unchanged` o `Failure`. El cambio de servidor está permitido en C04 porque
  aún no existe identidad backend durable.

No hay operaciones públicas de delete, clear, reset, replace, raw query,
export, close o recuperación destructiva. Room serializa las transacciones de
escritura de la instancia y SQLite hace rollback ante excepción, constraint o
cancelación. `CancellationException` se propaga y nunca se convierte en un
resultado persistente.

`Absent` es normal. Una configuración sin instalación, cardinalidad inesperada,
fila no canónica o timestamp inválido se clasifica como `STATE_INCOMPLETE`; no
se interpreta parcialmente como estado válido.

## Errores y redacción

Los fallos públicos contienen sólo un valor cerrado de `LocalPersistenceError`:

- `INITIALIZATION_FAILED`;
- `STATE_INCOMPLETE`;
- `STATE_CONFLICT`;
- `CONSTRAINT_VIOLATION`;
- `IO`;
- `DATABASE_BUSY_OR_LOCKED`;
- `CORRUPTION`;
- `SCHEMA_INCOMPATIBLE`;
- `MIGRATION_MISSING`;
- `UNKNOWN`.

Los resultados no conservan path, SQL, fila, URL, excepción, cause, mensaje
SQLite ni stack trace. Los errores internos usados para clasificar corrupción,
schema y migración tampoco tienen mensaje, cause o stack.

## Corrupción, journaling y recuperación

La factory de `SupportSQLiteOpenHelper` reemplaza el callback de corrupción
antes de construir el helper framework. Configura
`allowDataLossOnRecovery(false)` y su callback no delega al comportamiento
predeterminado que puede borrar archivos. Frente a corrupción marca el helper,
cierra handles de forma best-effort y hace fallar la operación como
`CORRUPTION`. No borra, recrea ni vacía la base y no habilita una recuperación
automática.

WAL permite lectores concurrentes y rollback transaccional ante process death,
dentro de las garantías de SQLite. `wto-agent.db-wal`, `wto-agent.db-shm` o un
rollback journal temporal pueden existir junto al archivo principal. Cerrar un
handle puede checkpointar o modificar sidecars; C04 no los borra deliberadamente
ni promete que permanezcan byte-idénticos. Los sidecars pueden contener la
misma metadata no sensible de las ocho columnas. SQLite y el almacenamiento
flash no permiten prometer secure deletion.

La corrupción bloquea el lifecycle hasta intervención explícita. C04 no ofrece
reset ni reparación. Los tests Robolectric con SQLite nativo verifican que el
archivo principal corrupto conserva longitud, header corrupto e identidad de
archivo cuando el filesystem la expone, y que no aparece una base nueva vacía.

## Migraciones, downgrade y rollback operativo

C04 crea la baseline fresca v1; no existe `Migration(0, 1)`. Room genera
`room_master_table`, el identity hash y el JSON de schema. No se configuran:

- `fallbackToDestructiveMigration`;
- fallback destructivo en downgrade;
- borrado automático por migración faltante;
- migraciones destructivas.

Una versión superior o un identity hash incompatible rechazan la apertura y
preservan el archivo. Una aplicación anterior a C04 no conoce ni abre esta
base; el archivo privado queda sin reinterpretar. Una versión futura que suba
el schema debe aportar migraciones explícitas y tests desde cada versión
soportada. Desinstalar la aplicación elimina normalmente sus datos privados;
C04 no realiza ese borrado y, con backup desactivado, no promete restauración.

## Backup y extracción

La defensa primaria es `noBackupFilesDir`. Además, `:app` mantiene
`android:allowBackup="false"`, referencia `android:fullBackupContent` para
Android legacy y `android:dataExtractionRules` para Android 12+. Ambas políticas
excluyen completamente los dominios `database` y `device_database`; la moderna
lo hace tanto para cloud backup como para device-to-device transfer. Esto evita
que una regresión futura al directorio estándar vuelva exportable la base.

El manifest fusionado se verifica para debug: conserva las tres políticas, no
agrega permisos, Activity, Service, Receiver, Provider ni `android:process`.
También se elimina del merge el servicio de invalidación multi-instancia que
Room declara transitivamente y que C04 no usa.

## Dependencias y tests host

C04 fija Room `2.8.4`, KSP `2.3.10`, AndroidX Test Core `1.7.0`, Robolectric
`4.16.1` y `kotlinx-coroutines-test` `1.11.0` sólo en tests. No incorpora
`room-ktx`, kapt, SQLite bundled, SQLCipher ni dependencias criptográficas al
runtime Android. BouncyCastle 1.81 y Conscrypt 2.5.2 son requisitos transitivos
del runner host de Robolectric; permanecen sólo en configuraciones unit-test y
C04 no los usa para cifrado o almacenamiento.

Los tests host usan JDK 17 y Robolectric SDK 29. El artifact exacto
`android-all-instrumented:10-robolectric-5803371-i7` se resuelve mediante
Gradle verificado, se copia sólo bajo `core/data/build/` y se consume con
`robolectric.offline=true`; Robolectric no resuelve SDKs por su cuenta. Los
nombres de bases temporales son deliberadamente cortos para no exceder límites
de path del SQLite nativo de Robolectric en Windows; la base de producción
conserva siempre `wto-agent.db`.

La cobertura incluye mappers estrictos, precisión temporal, schema/SQL
exportado, DAO y repositorio, carreras, rollback y cancelación, reapertura, WAL,
foreign keys, main-thread guard, downgrade, incompatibilidad de identity hash,
corrupción fail-closed, superficie sin secretos y políticas de backup fuente y
fusionadas. Las regresiones de persistencia insertan además `INTEGER` raw de
64 bits mediante SQLite y comprueban que valores inválidos que serían
congruentes módulo 2³² se rechacen antes de convertir nanosegundos a `Int`.

Resultado local del corte C04:

- `:core:data`: 143 tests en 13 suites, incluidos 82 tests C04 en 7 suites;
  cero fallos, errores o skips;
- `:app`: 5 tests en 1 suite de política backup/manifest; cero fallos, errores
  o skips;
- `:core:contracts`: 31 tests en 4 suites; `:core:domain`: 97 tests en 8 suites;
  cero fallos, errores o skips;
- KSP, lint de data/app, manifests debug/release y assemble debug/release:
  completados;
- validadores de repositorio, release contractual, copia desktop, 25 fixtures y
  OpenAPI empaquetado contra contrato canónico: completados;
- drift OpenAPI runtime: no ejecutado en esta corrección; C04 no modifica
  OpenAPI;
- pase Gradle offline: completado sin alterar locks, verification metadata ni
  schema JSON.

## Diferido

C04 no afirma enrolamiento durable. La secuencia implementada por C05–C07 es:

1. C05 administra claves criptográficas mediante Android Keystore.
2. C05 cifra la credential en memoria y produce un envelope autenticado.
   Keystore no se describirá como almacenamiento directo de un bearer
   credential recuperable.
3. C06 incorpora Room v2 y persiste en una operación SQLite el ciphertext,
   nonce, alias real, versión criptográfica, identidad y metadata.
4. El plaintext nunca se almacenará en Room. Sólo cuando estado criptográfico y
   metadata estén completos podrá afirmarse enrolamiento durable.
5. C07 coordina C03–C06 bajo un mutex de proceso: preflight antes de Keystore,
   una llamada remota, protección inmediata y persistencia. No convierte la
   atomicidad SQLite en atomicidad distribuida.

Las comprobaciones reales en dispositivo/emulador API 29 y API 36 de corrupción,
WAL con terminación forzada, backup/device transfer, downgrade y reapertura tras
process kill quedan para C12. CI Android continúa diferido a C13.
