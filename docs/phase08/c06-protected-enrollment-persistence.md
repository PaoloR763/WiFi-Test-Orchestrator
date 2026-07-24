# C06 — persistencia Room del enrolamiento protegido

## Estado y límite

C06 eleva la base Android a Room v2 y permite conservar de manera durable una
identidad asignada por el backend, la metadata de una credential `ACTIVE` y el
envelope cifrado producido por C05. La persistencia pertenece exclusivamente a
`:core:data`.

C06 no recibe ni conserva el token de enrolamiento, una credential en claro,
`DeliveredCredential`, claves Android Keystore, headers HTTP, request/response
JSON ni material temporal de C03. El repositorio productivo no conoce
`CredentialProtector`, no invoca Android Keystore, no ejecuta networking y no
coordina el ciclo de enrolamiento.

Tampoco implementa retry, mutex de enrolamiento, WorkManager, Foreground
Service, UI, observación Wi-Fi, capabilities, tareas remotas, telemetría,
unenrollment, reset ni recovery destructivo. `:app` no compone el repositorio
C06 en este corte.

Una fila C06 compatible sí representa enrolamiento durable local: las tres
tablas relacionadas fueron reconstruidas y verificadas en una transacción
SQLite. No representa por sí sola que la credential haya autenticado con éxito,
ni ofrece atomicidad distribuida entre backend, Keystore y Room.

## Arquitectura

La dirección de dependencias relevante es:

```text
:core:data -> :core:domain
:core:platform -> :core:domain
```

No existe dependencia productiva entre `:core:data` y `:core:platform`.

- C03 obtiene una aceptación del backend y todavía conserva la credential en
  memoria.
- C07 pide a C05 que proteja la credential inmediatamente después de la
  aceptación.
- C06 recibe únicamente `ProtectedCredentialEnvelope` más metadata no secreta.
- Room persiste campos explícitos; no serializa objetos Kotlin, DTOs ni JSON
  opaco.
- `AndroidLocalPersistenceFactory` entrega dos ports lazy que comparten la
  instancia Room de proceso: `LocalStateRepository` y
  `ProtectedEnrollmentRepository`. Construirlos no abre la base.

El port C06 es `suspend` y expone:

```kotlin
interface ProtectedEnrollmentRepository {
    suspend fun preflight(
        expectedLocalIdentity: LocalInstallationIdentity,
        expectedServerConfiguration: ServerConfiguration,
    ): ProtectedEnrollmentPreflightResult

    suspend fun read(): ReadProtectedEnrollmentResult

    suspend fun persist(
        write: ProtectedEnrollmentWrite,
    ): PersistProtectedEnrollmentResult
}
```

`ProtectedEnrollmentWrite` contiene la identidad local y servidor esperados,
la identidad backend, Agent Protocol, timestamp del servidor, metadata de la
credential y el envelope C05. No acepta token, secreto, aceptación C03 completa,
protector ni tipos Android/JCA.

## Schema Room v2

Room v2 conserva byte por byte el schema exportado v1 y agrega una única tabla:
`protected_enrollment`. La ausencia de enrolamiento se representa sólo por
ausencia de fila.

La tabla usa `singleton_id` simultáneamente como primary key y como foreign key
restrictiva hacia `local_installation.singleton_id` y
`server_configuration.singleton_id`. Ambas relaciones usan `ON UPDATE NO
ACTION` y `ON DELETE RESTRICT`. No se agregan índices: la primary key ya cubre
el único acceso por singleton y no existe una consulta demostrada que justifique
otro.

| Columna | Afinidad SQLite | Regla |
| --- | --- | --- |
| `singleton_id` | `INTEGER` | exactamente `1`; PK y dos FK |
| `installation_id` | `TEXT` | UUID canónico; debe coincidir con C04 |
| `server_base_url` | `TEXT` | URL HTTPS canónica; debe coincidir con C04 |
| `agent_id` | `TEXT` | UUID canónico asignado por backend |
| `device_id` | `TEXT` | UUID canónico asignado por backend |
| `protocol_version` | `TEXT` | SemVer estructural; actualmente sólo `1.0.0` |
| `server_received_at_epoch_seconds` | `INTEGER` | segundos UTC de `Instant` |
| `server_received_at_nanoseconds` | `INTEGER` | `0..999999999` |
| `credential_id` | `TEXT` | UUID canónico |
| `credential_version` | `INTEGER` | `1..2147483647` |
| `issued_at_epoch_seconds` | `INTEGER` | segundos UTC de `Instant` |
| `issued_at_nanoseconds` | `INTEGER` | `0..999999999` |
| `expires_at_epoch_seconds` | `INTEGER` | segundos UTC de `Instant` |
| `expires_at_nanoseconds` | `INTEGER` | `0..999999999` |
| `credential_delivery_state` | `TEXT` | representación exacta `ACTIVE` |
| `crypto_version` | `INTEGER` | actualmente `1` |
| `key_alias` | `TEXT` | alias versionado C05 |
| `nonce` | `BLOB` | v1: exactamente 12 bytes |
| `sealed_credential` | `BLOB` | v1: exactamente 105 bytes |

No existen columnas para token, plaintext, key material, authorization,
headers, body, payload, request, response, excepción o diagnóstico.

La lectura de seguridad usa una única observación SQL de la fila. Esa
observación incluye el `typeof(...)` de las 19 columnas, los tamaños de ambos
BLOB y los valores necesarios para reconstruir la entity. Exige storage class
`integer`, `text` o `blob` según la tabla anterior antes de invocar cualquier
getter tipado. Los BLOB sólo se materializan en la misma consulta cuando su
clase y su tamaño genérico son seguros. Una clase dinámica diferente produce
`Corrupt`, bloquea todas las mutaciones y conserva la fila sin normalizarla.

Después de esa validación, SQLite entrega los enteros persistidos como `Long`.
El mapper comprueba primero rango y sólo después convierte nanosegundos,
`credential_version` o `crypto_version` a `Int`. Valores negativos, cero donde
no corresponde, `Int.MAX_VALUE + 1`, enteros de 32 bits reinterpretados sin
signo o nanosegundos normalizables se rechazan; nunca se truncan ni se aplica
módulo.

## Reconstrucción fail-closed

Una lectura compatible exige simultáneamente:

- cero o una fila protegida;
- storage classes exactas para las 19 columnas;
- singleton `1` en las tres tablas;
- ambas relaciones presentes y coherentes;
- IDs UUID canónicos y no vacíos;
- URL HTTPS ya canónica y exactamente igual a `server_configuration`;
- Agent Protocol estructural y soportado;
- versiones positivas dentro de `Int`;
- timestamps representables y nanosegundos en rango;
- `issued_at <= server_received_at < expires_at`;
- delivery state exacto;
- alias acotado, versionado y con la misma versión que `crypto_version`;
- nonce/ciphertext estructuralmente acotados;
- tamaños v1 exactos antes de construir el envelope C05;
- coincidencia de credential ID/version entre metadata y envelope.

No se usa `0`, cadena vacía ni placeholder para representar un desconocido.
Campos obligatorios desconocidos hacen que la fila no sea compatible.

Después de validar storage classes, límites generales, relaciones y metadata,
la reconstrucción decide si `crypto_version` y `key_alias` identifican juntos
la policy C05 v1 conocida. En ese caso siempre ejecuta
`ProtectedCredentialEnvelope.create()` antes de clasificar `PENDING` o un
Agent Protocol futuro: nonce o ciphertext v1 inválidos son `Corrupt`, aunque
otra dimensión sea no soportada. Con envelope v1 válido, `PENDING` y un
protocolo futuro válido siguen siendo `Unsupported`.

Una policy criptográfica genuinamente futura, positiva y representable como
`Int`, debe usar un alias reconocido con la misma versión. El componente
decimal admite de uno a diez dígitos, sin signo ni ceros iniciales;
`toIntOrNull()` rechaza overflow. Esa policy no atraviesa la factory v1. Sólo se
le aplican límites estructurales genéricos y seguros; si los cumple queda
`Unsupported`, y si no, `Corrupt`.

## `Unsupported` frente a `Corrupt`

Las categorías son deliberadamente distintas:

| Evidencia almacenada | Resultado |
| --- | --- |
| delivery state exacto `PENDING` y resto estructural válido | `Unsupported` |
| crypto version futura positiva y estructuralmente válida, con alias de igual versión | `Unsupported` |
| alias futuro reconocido cuya versión coincide con `crypto_version` | `Unsupported` |
| Agent Protocol futuro con SemVer válido | `Unsupported` |
| state desconocido, vacío o con capitalización diferente | `Corrupt` |
| versión cero, negativa o fuera de `Int` | `Corrupt` |
| alias vacío, excesivo, no reconocido, malformado, con overflow o distinto de `crypto_version` | `Corrupt` |
| protocolo sintácticamente inválido | `Corrupt` |
| ID, URL, relación, timestamp, nonce o ciphertext inválido | `Corrupt` |
| cardinalidad mayor que uno u orphan insertado con FK desactivadas | `Corrupt` |

Una fila `Unsupported` o `Corrupt` bloquea `preflight`, `persist` y toda
mutación C04 de instalación o servidor. Permanece intacta, no se activa,
normaliza, repara, borra ni reemplaza automáticamente.

## Política `ACTIVE`/`PENDING`

C06 sólo escribe una credential cuyo estado sea exactamente `ACTIVE`.

- candidato `PENDING`: `PendingRejected`, incluso con tabla vacía;
- candidato `PENDING` durante equivalencia o rotación: `PendingRejected`;
- fila almacenada `PENDING` bien formada: `Unsupported`;
- state almacenado desconocido o malformado: `Corrupt`.

C06 no contiene un lifecycle que pueda convertir `PENDING` a `ACTIVE`. El
endpoint de rotación del contrato puede entregar `pending`, pero una fase
posterior deberá completar la activación por el flujo normativo antes de formar
un candidato `ACTIVE` para C06.

## Semántica de `preflight`

`preflight` lee C04 y C06 dentro de una única transacción.

| Resultado | Significado |
| --- | --- |
| `Absent` | instalación y servidor esperados coinciden; no hay fila C06 |
| `Compatible` | existe una fila C06 compatible y coherente |
| `Conflict` | instalación o servidor esperado no coincide |
| `LocalStateIncomplete` | falta instalar o configurar el servidor C04 |
| `Corrupt` | estructura local o enrolamiento inválido |
| `Unsupported` | fila futura o `PENDING` bien formada |
| `Failure(error)` | fallo cerrado de almacenamiento |

Un preflight preliminar fuera del futuro mutex puede ahorrar trabajo, pero no
autoriza consumir un token ni ejecutar la solicitud.

## Semántica de `read`

`read` reconstruye el estado bajo transacción:

- `Absent`: no hay fila protegida y el estado C04 presente no es corrupto;
- `Compatible(enrollment)`: devuelve tipos de domain y un envelope con copias
  defensivas;
- `Corrupt`: cardinalidad, relación o contenido inválido;
- `Unsupported`: versión/state/policy futura reconocida;
- `Failure(error)`: fallo cerrado de Room/SQLite.

La representación textual de write, stored model, entity y resultados que
contienen el envelope está redactada.

## Semántica de `persist`

`persist` devuelve una jerarquía cerrada:

| Resultado | Efecto |
| --- | --- |
| `Written` | primera fila `ACTIVE` insertada y verificada |
| `ExistingEquivalent` | no escribe; conserva el envelope original |
| `Replaced` | rotación superior válida escrita y verificada |
| `Conflict` | identidad o combinación ID/versión ambigua |
| `Rollback` | credential ID diferente con versión inferior |
| `PendingRejected` | candidato no durable para C06 |
| `InvalidCandidate` | incoherencia interna del write/envelope/timestamps |
| `Corrupt` | fila o estructura local corrupta; no muta |
| `Unsupported` | fila existente no soportada; no muta |
| `Failure(error)` | almacenamiento falló; no se afirma éxito |

La cancelación se relanza como `CancellationException`; nunca se transforma en
un fallo durable ni en éxito.

## Identidad, equivalencia y versión

La versión es monotónica por agente:

| Estado existente | Candidato | Resultado |
| --- | --- | --- |
| sin fila | `ACTIVE` válido | `Written` |
| mismo credential ID y versión, toda metadata equivalente | cualquier envelope v1 válido | `ExistingEquivalent` |
| mismo credential ID y versión, metadata diferente | — | `Conflict` |
| mismo credential ID y versión diferente | — | `Conflict` |
| credential ID diferente y misma versión | — | `Conflict` |
| credential ID diferente y versión inferior | — | `Rollback` |
| credential ID diferente, versión superior, misma identidad backend | `ACTIVE` | `Replaced` |
| identidad backend diferente | — | `Conflict` |
| instalación o servidor esperado diferente | — | `Conflict` |

Metadata equivalente incluye instalación, servidor, identidad backend,
protocolo, server timestamp, credential ID/version, issued/expires, state,
crypto version y alias. Nonce y ciphertext se excluyen deliberadamente: AES-GCM
produce ciphertext distinto para un nonce aleatorio nuevo. En equivalencia se
relee la fila y se demuestra que el envelope originalmente persistido sigue
byte-idéntico.

## Transacción y atomicidad

Cada `persist` usa una única `RoomDatabase.withTransaction`:

1. lee instalación local;
2. lee configuración de servidor;
3. lee todas las filas de enrolamiento;
4. valida cardinalidad, relaciones y estado existente;
5. valida el candidato;
6. clasifica ausencia, equivalencia, conflicto, rollback o reemplazo;
7. inserta o actualiza sólo si la regla lo permite;
8. relee las tres tablas;
9. reconstruye y compara metadata, nonce y ciphertext byte por byte;
10. permite commit únicamente si la verificación final coincide.

Una verificación posterior a escritura que no coincide lanza una excepción
interna sin diagnóstico y fuerza rollback. No se usa `REPLACE`, upsert, delete
ni fallback destructivo.

La garantía termina en SQLite. Si el backend consumió el token, C05 creó o usó
una clave y luego Room falla, C06 no puede deshacer esas operaciones externas.

## Concurrencia

Room y SQLite serializan las transacciones de escritura. Las pruebas cubren:

- primera escritura concurrente equivalente: un `Written` y un
  `ExistingEquivalent`;
- envelopes equivalentes: gana el primero y el segundo no sobrescribe nonce ni
  ciphertext;
- IDs diferentes con igual versión: un único ganador y un `Conflict`;
- rotaciones superiores concurrentes: el estado final conserva la versión más
  alta en ambos órdenes de scheduling;
- versión superior seguida de inferior: la inferior produce `Rollback`;
- dos rotaciones con igual versión e IDs diferentes: un `Replaced`, un
  `Conflict` y una única fila completa.

“Gana la versión más alta” sólo aplica a credential IDs diferentes con
versiones diferentes y la misma identidad backend. Dos IDs con la misma versión
no tienen desempate y se tratan como conflicto.

## Padres C04 inmutables después del enrolamiento

`RoomLocalStateRepository.setServerConfiguration` conserva el comportamiento
C04 mientras no exista enrolamiento durable:

- crea después de instalación;
- devuelve `Unchanged` para la URL canónica ya persistida;
- actualiza una URL diferente.

Después de una fila C06 compatible:

- URL exactamente equivalente: `Unchanged`, sin cambiar timestamp ni envelope;
- URL diferente: `Conflict`, sin escritura.

Una fila C06 `Corrupt` o `Unsupported` devuelve la categoría homónima para
cualquier intento: el repositorio no puede demostrar de forma segura que un
cambio sea válido. Nunca borra el enrolamiento para habilitar otro servidor.

La misma protección se aplica a los tres caminos C04 capaces de escribir
padres: `ensureLocalInstallation`, `initializeLocalState` y
`setServerConfiguration`. Cada uno entra primero en
`RoomDatabase.withTransaction`, observa ambas tablas padre y
`protected_enrollment` mediante la ruta segura de storage classes, y sólo
después decide. Si existe una fila protegida mientras falta instalación,
servidor o ambos al comenzar la transacción, el estado es `Corrupt`: ningún
input coincidente puede insertar los padres faltantes ni legitimar el orphan.

Con una fila compatible y ambos padres completos sólo se permiten operaciones
exactamente idempotentes; se preservan timestamps y envelope. Con fila ausente
se conserva la semántica C04 previa. Como `ensureLocalInstallation` e
`initializeLocalState` no exponen categorías C06, mapean `Corrupt` a
`Failure(CORRUPTION)` y `Unsupported` a `Failure(STATE_CONFLICT)`.
`setServerConfiguration` conserva sus resultados tipados `Corrupt` y
`Unsupported`. Guard, decisión y eventual escritura comparten la misma
transacción, por lo que no existe una ventana de reparación entre la
inspección y el write.

## Migración 1 → 2

`WtoAgentDatabaseMigrations.MIGRATION_1_2` crea únicamente
`protected_enrollment`.

- no hace backfill;
- no toca tablas, filas ni índice C04;
- no agrega `CHECK` exclusivos de la migración;
- no habilita migración destructiva;
- no implementa downgrade;
- registra la migración explícitamente en el builder.

Room/KSP genera y versiona `2.json`. `1.json` permanece byte-idéntico. El test
instrumentado usa `MigrationTestHelper.createDatabase(..., 1)`, por lo que crea
la base desde el schema v1 exportado en vez de imitar su DDL. Después de insertar
fixtures y cerrar v1, ejecuta `runMigrationsAndValidate(...)` con
`MIGRATION_1_2`. Cubre bases vacías, instalación, servidor orphan adversarial y
ambas filas; valida datos exactos, tabla nueva vacía, shape v2 contra el asset
exportado y ausencia de índices o backfill. El código actual del test no duplica
el identity hash interno de Room ni contiene DDL v1 manual. Un
`best-effort maintenance guard` detecta formas directas y contiguas cubiertas
por sus fixtures, como un hash hexadecimal literal, referencias directas a
metadata Room, DDL v1 directo y una escritura directa de `user_version`. No
evalúa constantes, concatenaciones, interpolaciones, código generado ni
ofuscación deliberada; la confirmación de que el fixture sigue partiendo del
asset exportado también requiere revisión de código. Una base de versión
superior sigue fallando cerrada y se conserva.

El rollback operativo de una entrega que ya abrió Room v2 requiere restaurar
una copia completa y coherente de aplicación más base de datos tomada antes de
la migración. No existe downgrade automático ni reset dentro de C06.

## Seguridad de almacenamiento

Room no cifra el archivo SQLite. La protección del bearer secret depende del
envelope C05: C06 sólo escribe nonce y ciphertext; la clave usada para producir
ese envelope permanece bajo la responsabilidad de C05 y Android Keystore.

La evidencia automatizada separa tres controles de alcance diferente:

1. El `known C06 public API snapshot` compara los campos, constructores y
   métodos JVM de los 28 tipos explícitamente enumerados de modelos/resultados y
   del port C06. Compara nombre, descriptor JVM, firma genérica y flags de forma
   independiente del orden de reflexión. Modela explícitamente `Continuation`
   para métodos `suspend`, arrays, primitivas/boxing, constructores por default,
   `copy`, `copy$default`, `componentN`, bridges y miembros synthetic; no los
   descarta en bloque. Sólo excluye miembros heredados de `Object`. La
   nullability Kotlin no se incluye porque sus anotaciones no son observables de
   forma estable mediante esta reflexión JVM. El snapshot detecta cambios
   accidentales dentro de esos tipos y revisa los nombres default conocidos de
   sus dos file facades; no descubre exhaustivamente una clase pública nueva en
   otro archivo existente ni una facade renombrada. No reemplaza una herramienta
   de binary compatibility ni la revisión de código.
2. El inventario cerrado descubre sin filtros por nombre o contenido los 22
   archivos `.kt` productivos bajo el árbol `data/persistence` y los clasifica
   una sola vez como C04, C06 o compartidos. Un archivo nuevo dentro de ese
   árbol, una ruta listada ausente o una clasificación duplicada falla. Para los
   archivos inventariados aplica checks léxicos best-effort sobre las formas
   directas cubiertas por tests: referencias prohibidas, imports locales
   explícitos fuera de los prefixes permitidos, aliases, referencias FQ directas
   y wildcards locales ordinarios reconocidos bajo
   `com.wifitestorchestrator.agent`.
   Elimina comentarios antes de esos checks. El inventario no sigue
   transitivamente helpers externos a `data/persistence`, no es un parser Kotlin
   ni un análisis formal de dependencias o flujo de datos.
3. El escenario DB/WAL/SHM crea una credential plaintext marcada fuera de C06,
   la transforma mediante un protector falso de test y entrega al repositorio
   únicamente el envelope. Comprueba que metadata, nonce y ciphertext realmente
   persistidos aparecen en al menos una superficie SQLite inspeccionada, y que
   el marcador plaintext ejercitado no aparece en ninguno de los archivos DB,
   WAL o SHM que existen. No usa como evidencia marcadores de token o mensajes
   wire que nunca ingresaron al escenario.

Los dos primeros controles son defensa en profundidad frente a regresiones
accidentales. No son una frontera de seguridad y no pretenden resistir una
modificación deliberada y simultánea de producción y tests. El enforcement
arquitectónico exhaustivo de API, packages y dependencias se difiere a C13/C14
o trabajo futuro y se registra en
[`FW-MOB-003`](../future-work-and-limitations.md).

Los tests también verifican copia defensiva de arrays, conservación byte por
byte en equivalencia y redacción de resultados/errores. Esta evidencia no
demuestra cifrado integral de la base, seguridad frente a root/hooking, ni
ausencia universal de secretos fuera del camino probado.

La base continúa bajo `noBackupFilesDir`, `allowBackup=false` y las exclusiones
de cloud/device transfer C04. C06 no modifica manifests ni políticas de backup.
Un dispositivo desbloqueado comprometido, root, hooking o lectura del proceso
puede observar plaintext mientras otra fase lo usa; C06 no afirma protección
contra ese atacante ni cifrado integral de metadata.

## Orden implementado por el coordinador C07

C07 mantiene este orden:

1. construir fuera del mutex un `EnrollmentAttempt` validado;
2. adquirir el mutex de enrolamiento de proceso;
3. repetir dentro del mutex el `preflight` autoritativo;
4. resolver estados bloqueantes sin Keystore o red;
5. ejecutar `inspect()` sólo para `Compatible`, o autorizar el guard y ejecutar
   `prepare()` sólo para `Absent`;
6. crear y ejecutar una única llamada;
7. validar la aceptación y proteger inmediatamente la credential;
8. persistir mediante C06;
9. ante persistencia incierta, ejecutar una única reconciliación read-only;
10. actualizar sin suspensión el guard y liberar el mutex.

El mutex permanece adquirido durante Keystore, solicitud, protección,
persistencia y reconciliación. C06 no implementa ese mutex ni consume tokens;
C07 lo hace sin modificar C06. Un preflight fuera del mutex nunca sustituye el
paso 3.

## Evidencia host y límites pendientes

Las suites JVM/Robolectric ejercitan Room/SQLite real, migración, transacciones,
SQL adversarial, WAL/no-backup, concurrencia, cancelación y fallos de
almacenamiento. No prueban Android Keystore, KeyMint, TEE/StrongBox, reboot,
process death, restore, uninstall ni comportamiento OEM real.

Permanecen diferidos:

- journal durable y reconciliación remota tras fallos entre backend, Keystore y
  Room (`FW-MOB-004`);
- uso autenticado de la credential persistida;
- lifecycle, WorkManager, Foreground Service y UI;
- instrumentación C12 en emulador y dispositivo físico;
- unenrollment, reset y recovery, que requieren una decisión y autorización
  explícitas.
