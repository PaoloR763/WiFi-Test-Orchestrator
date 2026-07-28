# C09 — Observación pasiva de conectividad y Wi-Fi en Android

## Objetivo y alcance cerrado

C09 incorpora una infraestructura local para observar de forma pasiva la red
por defecto y, cuando Android aporta evidencia legítima, la asociación Wi-Fi.
El objetivo es conservar contexto técnico suficiente para testing, diagnóstico
y homologación en laboratorios, pilotos y redes autorizadas, sin convertir la
lectura del sistema operativo en captura 802.11 ni en prueba de throughput.

El bloque agrega modelos Android-free en `:core:domain`, un facade y mapper
testeables en `:core:platform`, un observer explícito y lazy y su composición
lazy en `:app`. No agrega UI, `Activity`, `Service`, `Receiver`, `Provider`,
Foreground Service, WorkManager, scan, conexión, cambio de red, tarea remota,
probe, tráfico, persistencia, serialización wire, telemetría o upload.

## Perfiles de recopilación

`ConnectivityCollectionProfile` es cerrado:

- `BASIC` es el default. Registra el callback de red por defecto y conserva
  transportes, capabilities y KPIs no sensibles expuestos en el evento. No
  solicita información location-sensitive, no usa
  `FLAG_INCLUDE_LOCATION_INFO`, no consulta `WifiManager` legacy y representa
  SSID/BSSID como `null` con `POLICY_REDACTED`. No requiere permisos peligrosos.
- `WIFI_TEST_AUTHORIZED` debe seleccionarse de forma explícita para una sesión
  autorizada. Permite intentar obtener SSID/BSSID, pero no reemplaza manifest,
  grant runtime ni estado de ubicación. Un requisito ausente degrada sólo los
  campos afectados con un `reason` cerrado; nunca se traduce a “sin
  asociación”.

C09 declara `ACCESS_FINE_LOCATION`, pero no muestra diálogos, abre Settings ni
habilita el perfil autorizado. La decisión y la solicitud interactiva quedan
fuera de este bloque. También declara `ACCESS_COARSE_LOCATION` porque Android
12/API 31+ exige acompañar COARSE y FINE al solicitar ubicación precisa. C09 no
realiza esa solicitud mediante UI: una futura UI deberá pedir ambas. El gate
autorizado sigue exigiendo FINE realmente concedido para intentar SSID/BSSID;
una concesión sólo COARSE no es suficiente. `BASIC` no consulta estos grants y
no se suprime la regla `CoarseFineLocation`.

## Modelo y semántica

Cada campo observado conserva `value`, `unit`, `source`, `availability`,
`confidence` y `reason`. `OBSERVED` exige valor y prohíbe `reason`;
`UNAVAILABLE`, `UNKNOWN` y `NOT_APPLICABLE` exigen `value=null` y un motivo.
`false` y `0` se conservan cuando son observaciones reales; ningún sentinel se
convierte en cero.

`ConnectivitySnapshot` contiene:

- `observedAtUtc`;
- `elapsedRealtimeNanos`;
- `sequence`;
- `collectionProfile`;
- `defaultNetwork`;
- `wifiAssociation`;
- fallos estructurados sin `Throwable`, mensajes Android ni identificadores.

Las colecciones de transportes y fallos se copian defensivamente. Los modelos
de dominio no importan clases Android, JSON, Room, red o filesystem.

## Red por defecto versus asociación Wi-Fi

`DefaultNetworkObservation` y `WifiAssociationObservation` son evidencias
separadas. La primera representa presencia confirmada, ausencia confirmada o
estado todavía desconocido; capabilities pending; bloqueo; Internet,
validated, captive portal, `NOT_METERED`, metered derivado como su negación,
`NOT_ROAMING` y `NOT_SUSPENDED` literales; y todos los transportes reportados.

Se preservan Wi-Fi, cellular, Ethernet, VPN, Bluetooth, Wi-Fi Aware, Lowpan,
USB, Thread y satellite según el API level. Una lista multi-transporte no se
reduce a un valor principal. En particular, VPN sobre Wi-Fi conserva ambos
transportes y la asociación subyacente queda `UNKNOWN` con
`VPN_UNDERLYING_NETWORK_NOT_OBSERVABLE`; C09 no afirma el path del tráfico.

En API 31+ un `WifiInfo` recibido dentro de las `NetworkCapabilities` del mismo
callback se marca `DEFAULT_NETWORK`. En API 29–30 la lectura autorizada de
`WifiManager` es device-scoped, usa confianza `MEDIUM` y scope
`DEVICE_ASSOCIATION_NOT_PROVEN_AS_DEFAULT`: no prueba que Wi-Fi sea el default
ni que transporte el tráfico de la aplicación. Esa fuente legacy sólo informa
`ASSOCIATED` cuando al menos un campo sobrevive a los mismos validadores
semánticos usados para mapearlo. La mera presencia raw de sentinels no prueba
asociación.

En API 29–30 se separan dos gates. El acceso base a `WifiInfo` exige
`ACCESS_WIFI_STATE` declarado y concedido, `WifiManager` disponible y una
lectura válida de `connectionInfo`. El acceso sensible exige además
`ACCESS_FINE_LOCATION` declarado y concedido y ubicación habilitada. Si falla
sólo el gate sensible, SSID/BSSID quedan en `null` con su único `reason`, pero
RSSI, frecuencia, link speed general y RX/TX continúan leyéndose y
validándose. COARSE no sustituye FINE. Si falla el gate base o el proveedor
arroja `SecurityException`, todos los campos quedan `PERMISSION_DENIED`; una
`RuntimeException` ordinaria del proveedor produce `PLATFORM_ERROR` en todos
ellos. Los sentinels redactados de identidad tampoco descartan KPIs válidos.

## Matriz de API

| API | Fuente y comportamiento C09 |
|---|---|
| 29 | `registerDefaultNetworkCallback(callback, handler)` y capabilities. Sólo en perfil autorizado puede leerse `WifiManager.connectionInfo`; la evidencia es legacy/no network-scoped. Standard y security quedan `UNSUPPORTED_API`. |
| 30 | Igual que API 29; Wi-Fi standard puede observarse. Security type sigue no disponible. |
| 31 | Se prioriza exclusivamente el `WifiInfo` de `NetworkCapabilities.transportInfo`. `FLAG_INCLUDE_LOCATION_INFO` se usa sólo en modo autorizado, con permisos declarados/concedidos y ubicación habilitada. Security type y transporte USB quedan disponibles. No se consulta el estado sincrónicamente dentro del callback. |
| 33 | Misma fuente network-scoped. C09 no usa APIs de scan, conexión, suggestion, specifier, P2P, RTT o administración que requieran `NEARBY_WIFI_DEVICES`. |
| 35 | Se mantienen las reglas anteriores; USB, Thread y satellite se reconocen con guards explícitos por versión. |
| 36.0 | No se habilita ningún dato adicional ni MLO. Se aplica la misma política que API 35. |
| 36.1 | `compileSdk` 36.1; C09 no consume una API minor-specific y conserva el mismo comportamiento que 36.0. |

Las constantes de transporte agregadas después de API 29 se encapsulan como
valores inlined y sólo se consultan dentro de sus guards, evitando referencias
de linkage/verifier en releases anteriores. Las llamadas a standard, security
type y al constructor del callback con flags están separadas detrás de sus
checks de API.

## Matriz de permisos y policy

| Requisito | Uso |
|---|---|
| `INTERNET` | Ya existía en `:core:data`; C09 no realiza networking. |
| `ACCESS_NETWORK_STATE` | Registro y recepción del callback de red por defecto. |
| `ACCESS_WIFI_STATE` | Lectura pasiva de información Wi-Fi soportada. |
| `ACCESS_COARSE_LOCATION` | Acompaña declarativamente a FINE para que un futuro request runtime de ubicación precisa sea válido en API 31+; COARSE concedido por sí solo no habilita SSID/BSSID. |
| `ACCESS_FINE_LOCATION` | Sólo habilita el intento de SSID/BSSID location-sensitive en `WIFI_TEST_AUTHORIZED`, sujeto además al grant runtime y al toggle de ubicación. |
| `NEARBY_WIFI_DEVICES` | No declarado: C09 no escanea, conecta ni administra Wi-Fi y no llama ninguna API listada para ese permiso. |
| `CHANGE_WIFI_STATE` y permisos FGS | No declarados ni utilizados. |

No se declara `neverForLocation`: el perfil autorizado usa deliberadamente
SSID/BSSID location-sensitive. No se suprime `CoarseFineLocation`. C09 no pide
permisos mediante UI, `BASIC` no consulta los grants peligrosos y continúa
operativo si COARSE/FINE están denegados.

## SSID y BSSID

En perfil autorizado el SSID conserva la cadena exacta reportada. La
representación de display es separada y sólo puede quitar un par exterior de
comillas Android; no hace `trim`, unescape, case folding ni normalización
Unicode. Cadena vacía y `UNKNOWN_SSID` producen `null/reason`.

El BSSID se valida como seis octetos hexadecimales antes de obtener una forma
canónica lowercase. Se preserva también el valor reportado; el sentinel
`02:00:00:00:00:00` se considera redacción de plataforma. SSID/BSSID tienen
`toString()` redactado y no se incorporan a fallos, excepciones o logs.

C09 no lee ni modela network ID, MAC del dispositivo, passpoint, information
elements o credenciales. Tampoco aplica hashing irreversible: una futura
correlación autorizada con el AP necesita conservar la identidad real.

## KPIs y sentinels

Cuando la fuente los expone, C09 conserva RSSI en dBm, frecuencia en MHz, link
speed general y RX/TX en Mbps, standard y security type. Banda y canal primario
se derivan separadamente desde frecuencia con source
`DERIVED_FROM_FREQUENCY`, incluidas las bandas 2,4/5/6/60 GHz y el canal 2 de
5935 MHz. Channel width siempre queda `UNSUPPORTED_API`: C09 no encontró una
fuente legítima en el objeto observado.

Se rechazan RSSI `-127`, signal strength `Int.MIN_VALUE`, frecuencia no
positiva, link speed `-1`, standard `UNKNOWN`, security `UNKNOWN`, SSID vacío,
`UNKNOWN_SSID` y BSSID redactado. Un `TransportInfo` de tipo inesperado,
hardware Wi-Fi contradictorio o mezcla de fuentes produce motivos/fallos
estructurados. Link speed es la tasa física reportada por el SO, no throughput;
RSSI no es una medición por trama; ninguno equivale a captura 802.11.
Un snapshot legacy compuesto únicamente por esos sentinels conserva
`association.value == null`, availability `UNKNOWN` y el `reason` semántico;
los KPI inválidos siguen en `null`. Los ceros aceptados por el contrato, como
link speed 0, se preservan y sí constituyen evidencia semántica.

## Tiempo y orden local

La plataforma inyecta una fuente que captura `Instant.now()` y
`SystemClock.elapsedRealtimeNanos()` juntos, además de una secuencia por sesión.
El primer snapshot usa secuencia 0 y cada publicación posterior la incrementa
sin repetición. `sequence` ordena snapshots nuevos: una transición lifecycle
puede conservar el último snapshot y, por lo tanto, reutilizar su sequence. Un
salto del reloj UTC no cambia el orden definido por monotonic time y sequence.

Un `FAILED` sólo puede usar una captura terminal nueva que haya finalizado con
éxito, el último `AndroidObservationTime` capturado con éxito por la sesión o
los dos campos temporales de un snapshot válido ya publicado. No existe
fallback a epoch, cero, reloj de pared alternativo ni otra constante. Los
valores reutilizados se copian exactamente, sin incrementarlos, redondearlos o
reemplazarlos.

Si falla la captura necesaria para fechar un fallo y nunca existió ninguna de
esas tres fuentes válidas, el contrato actual no puede representar
honestamente un `ConnectivityObservationFailure`. Después de desmontar una vez
los recursos y eliminar la sesión, el observer publica `STOPPED`, completa la
misma `LifecycleCompletion` para todos los callers y relanza explícitamente la
causa primaria. Así no queda `STARTING`, `ACTIVE` o `STOPPING`, no se informa
éxito falso y un `start()` posterior puede reservar otra sesión. Un fallo que
nace en la propia captura temporal también se relanza por identidad después
del cleanup, aunque una captura terminal posterior sí permita construir un
`FAILED` correctamente fechado.

Esta evidencia sólo ordena eventos dentro de la sesión local. No afirma
sincronización con backend, AP, gateway, controlador o Capture Node.

## Lifecycle, concurrencia y process death

Construir el observer no crea thread, callback ni registro. `start()` crea un
`HandlerThread` dedicado y serializa callbacks; un start repetido con el mismo
perfil es idempotente y cambiar de perfil exige stop/restart. Cada sesión
exitosa realiza un register y como máximo un unregister.

Los estados son `NEW`, `STARTING`, `ACTIVE`, `STOPPING`, `STOPPED`, `FAILED` y
`CLOSED`. Network identity evita mezclar capabilities o `onLost` de otra red, y
un generation token descarta callbacks de sesiones anteriores. Fallos de
registro, unregister, mapping y cleanup se diferencian. `close()` es terminal e
idempotente.

Las transiciones lifecycle reservan intención, generación y sesión bajo el
monitor interno, ejecutan fuera de ese monitor la creación del dispatcher,
register, unregister, cierre/join y callbacks del listener, y luego reconcilian
por identidad. Un callback síncrono durante register puede actualizar el estado
pre-`ACTIVE`; stop/close concurrentes esperan una única limpieza y nunca
devuelven `Accepted(STOPPING)`.

El intento de registro distingue explícitamente tres resultados internos. En el
caso A, el registrar falla antes de demostrar un registro efectivo: no se crea
un token y no se intenta unregister. En el caso B, el callback quedó registrado
antes de un fallo de control síncrono: el facade devuelve un token válido que
porta el fallo y el observer, después de instalar ese token en la sesión,
ejecuta el único unregister. En el caso C, `start()` ya retornó `ACTIVE` y el
callback registrado comunica el fallo directamente al observer. Ninguno de los
tres casos infiere que existe un registro únicamente porque hubo una excepción.

Los callbacks básico y location-aware comparten el mismo delegate productivo.
Si la captura de capabilities arroja `CancellationException` o `Error` antes de
poder construir el evento, una frontera interna tipada entrega el mismo objeto
a `SessionEvents`. El generation token limita cleanup y transición terminal a
la sesión vigente; un callback viejo conserva la propagación de su causa, pero
no cierra ni modifica una sesión nueva. En una sesión vigente se reserva o
ejecuta cleanup exactamente una vez, se elimina la sesión, se entrega
`STOPPED` al listener y se relanza el objeto original. Un fallo operativo de
unregister o del dispatcher produce `FAILED` con la operación correspondiente.
No se publica el snapshot que no llegó a construirse.

Un fallo de mapping posterior a `start()` también entra por la reconciliación
única. Una `RuntimeException` ordinaria produce `FAILED/MAP_PLATFORM_DATA`,
retiene el último snapshot válido, desmonta registration y dispatcher una vez,
elimina la sesión y entrega una sola terminal; no escapa al callback. Una
`CancellationException`, `Error` u otro `Throwable` de control ejecuta el
mismo cleanup, termina en `STOPPED` si no hubo fallos operativos secundarios y
relanza la instancia original. Si unregister o cierre fallan, el terminal es
`FAILED` y los secundarios se agregan por identidad. La captura de tiempo del
terminal se hace fuera del monitor. Si también falla, se conserva exactamente
el último tiempo válido de la sesión o del snapshot. Si ninguno existe, se usa
el terminal honesto `STOPPED` descrito antes y se propaga la causa: nunca se
construye un fallo con tiempo fabricado.

El observer registra explícitamente qué hilo está ejecutando una operación
externa de lifecycle cuya vuelta es necesaria para completar la misma
reconciliación. Si ese hilo reentra `stop()`, reserva atómicamente el stop pero
no espera su propia completion: retorna
`Rejected(OBSERVER_STOPPED)` como acknowledgement especial de intención
diferida, no como indicación de que la intención fue ignorada. Si reentra
`close()`, reserva el cierre y retorna `Unit`; el dueño de la operación exterior
completa después la única limpieza y lleva el observer a `CLOSED`. Un segundo
`close()` reentrante durante ese cierre también retorna sin esperar. Las
invocaciones concurrentes normales desde otros hilos continúan esperando la
completion terminal.

La regresión intermitente de `stop()`/`close()` era exclusivamente un problema
de ordenamiento del test: liberaba el cierre bloqueado del dispatcher sin haber
demostrado que el segundo `stop()` ya se había asociado a la
`LifecycleCompletion`. En ese orden no controlado, `close()` podía completar
legítimamente primero y el segundo `stop()` debía devolver
`Rejected(OBSERVER_CLOSED)`. La cobertura separa ahora los dos órdenes
contractuales. En el primero, una seam interna tipada confirma que el hilo
exacto del segundo `stop()` quedó asociado como waiter antes de iniciar
`close()` y liberar el cleanup; ambos `stop()` retornan `Accepted`. En el
segundo, el test espera a que `close()` alcance `CLOSED` antes de invocar el
segundo `stop()`, que retorna la razón exacta `OBSERVER_CLOSED`. Un tercer caso
sin orden impuesto acepta únicamente esos resultados contractuales.

La seam `AndroidLifecycleCleanupWaiterObserver` tiene visibilidad `internal`,
default no-op y sólo recibe `kind`, `phase` y el `Thread` caller. Emite
`REGISTERED` después de que el caller quedó ligado a la completion existente y
fuera del monitor del observer; `INTERRUPTED` permite confirmar la interrupción
del waiter antes de liberar el mismo cleanup. No expone ni permite mutar
session, completion, locks o estado lifecycle, no altera decisiones ni
resultados productivos y el constructor público basado en `Context` conserva
su firma. Latches vinculados al hilo exacto sustituyen cualquier dependencia de
sleep, polling, estado del thread o timing incidental.

La entrega del listener mantiene además un registro por instancia, identidad de
hilo y profundidad, activo sólo durante `onObservation()` y limpiado siempre en
`finally`. Si un listener reentra `close()` mientras ya existe un cierre cuya
finalización depende del retorno de ese callback, la llamada reentrante retorna
sin esperar ni crear otra completion; el cierre exterior conserva la
responsabilidad de completar exactamente una limpieza y llegar a `CLOSED`. Si
no existía un cierre previo —por ejemplo, el listener recibe `STOPPED` desde
`stop()`—, ese mismo `close()` inicia y completa el cierre normal. Un cierre
independiente desde otro hilo no se clasifica como reentrante y continúa
esperando la reconciliación terminal.

Si `dispatcher.close()`/`Thread.join()` lanza `InterruptedException`, la
limpieza completa igualmente unregister y reconciliación terminal, elimina la
sesión, conserva el fallo y recién entonces restaura el interrupt flag. Fallos
secundarios de cualquier subtipo de `Throwable` se adjuntan al primario por
identidad sin self-suppression ni duplicación. Esto incluye
`InterruptedException`, cuyo interrupt flag se restaura, `Error` y throwables
personalizados. El orden causal para fallos operacionales ordinarios es
estable: causa original, unregister, dispatcher, reloj y listener terminal. Un
fallo terminal del listener se agrega sin reemplazar el primario explícito.
`CancellationException` y `Error` mantienen la prioridad e identidad previstas
por la frontera de control.
`CancellationException`, `Error` y otros throwables no ordinarios nunca se
aíslan ni reclasifican: después de restaurar invariantes lifecycle se relanza
exactamente el mismo objeto. Sólo una `RuntimeException` ordinaria del listener
se aísla. La misma política rige al instalar el listener sobre una sesión
activa y durante cada callback activo: un fallo de control invalida el slot,
reserva o comparte el único cleanup, elimina la sesión y no deja un falso
`ACTIVE`. Un fallo del listener terminal se combina con el primario sin crear
otro cleanup, recursión o espera propia; stop/close reentrantes y concurrentes
mantienen unregister y cierre exactamente una vez.

El facade aplica la misma frontera fail-closed a feature Wi-Fi,
`WifiManager.connectionInfo`, clasificación de servicio ausente, lecturas
generales/sensibles y a las cuatro dependencias del gate autorizado:
permisos solicitados, estado de cada permiso, proveedor de `LocationManager` y
estado de ubicación. Cada dependencia se evalúa una vez por assessment.
`CancellationException` se captura antes que `RuntimeException` y se relanza
por identidad; `Error` nunca se degrada. `SecurityException` en cualquiera de
las cuatro dependencias se traduce a `PERMISSION_DENIED`; una
`RuntimeException` ordinaria se traduce a `PLATFORM_ERROR`. El borde del
callback sólo intercepta los fallos de control tipados para restaurar
invariantes antes de relanzar. Las demás `RuntimeException` ordinarias mantienen
su degradación local a `PLATFORM_ERROR` o `null`, según el contrato de la
lectura.
`SecurityException` continúa como `PERMISSION_DENIED`, la redacción del
framework como `REDACTED_BY_PLATFORM`, un valor ausente como `NOT_REPORTED` y
la ausencia confirmada de hardware como `WIFI_HARDWARE_ABSENT`.

El constructor productivo basado en `Context` no cambia. Para probar estas
fronteras sin reflection ni dependencias de mocking, el facade expone sólo
dentro del módulo seams tipadas para registrar callbacks y leer feature,
`WifiInfo`, permisos y ubicación; en producción esas seams delegan directamente
a las APIs Android existentes. La construcción location-aware queda detrás de
una seam interna que en producción aplica `FLAG_INCLUDE_LOCATION_INFO` y
delega al mismo callback de captura. Los casos B y C llegan por la ruta real
del observer: el callback efectivo se desregistra una vez, no se conserva un
snapshot falso y el dispatcher adquirido se libera una vez.

`AndroidConnectivityObserverTest` tampoco inspecciona campos, métodos, locks,
generaciones, slots o colas privadas. Los callbacks viejos, reemplazo,
ordenamiento, duplicación posible y carreras recorren la ruta real
facade→observer→mapper→cola→listener. Un diagnóstico interno tipado y
read-only expone sólo invariantes de lifecycle esenciales. Un gate estático
dentro de la suite lee el archivo completo y falla si reaparecen accesos por
`getDeclaredField`, `getDeclaredMethod`, `getDeclaredConstructor`,
`declaredFields`, `declaredMethods`, `isAccessible`, `setAccessible`,
`trySetAccessible`, `java.lang.reflect`, `kotlin.reflect`, `Class.forName`,
`MethodHandles`, `Unsafe`, `::class.java` o `.javaClass`. El detector es
case-sensitive de forma explícita, acepta texto benigno, cubre límites y
múltiples findings y se prueba contra una matriz normativa independiente de
15 tokens. Ambas matrices construyen sus valores completos sólo en runtime
para no marcarse a sí mismas. Una validación pura exige cardinalidad exacta,
ausencia de duplicados e igualdad de conjuntos. La matriz actual del detector
se usa únicamente como `actual` en esa comprobación. Las 15 omisiones parten de
la matriz normativa, comprueban cardinalidad 14, ausencia del token omitido,
presencia exactamente una vez de los otros 14 y un diagnóstico que identifica
sólo el token faltante. Las matrices con un duplicado o un token extra también
parten exclusivamente de la matriz normativa; la lista vacía permanece
independiente de ambas. El detector no usa reflection y no se cambió Gradle
para incorporarlo.

Cada instalación de listener crea un slot serializado. Su bootstrap usa el
estado estable más reciente. Los snapshots nuevos de una sesión se entregan con
sequence estrictamente creciente y nunca retroceden. La deduplicación compara
la identidad completa del estado: `ACTIVE(N)` y `FAILED(N)` no son duplicados
cuando el fallo conserva el último snapshot, por lo que se entregan una vez y
en ese orden; dos `ACTIVE(N)` realmente iguales sí se descartan. Reemplazar o
retirar el listener invalida su cola pendiente; un estado capturado para el
slot anterior no se redirige al nuevo. La invocación ocurre fuera del monitor y
permite consulta, reemplazo o retiro reentrante sin deadlock.

`AndroidAgentCompositionRoot` memoiza el observer sin acceder a él;
`WtoApplication` permanece intacta y no lo inicia. Ante process death se pierden
observer, secuencia y snapshot en memoria; no existe auto-resume, persistencia o
reconciliación C09.

## Privacidad y límites de datos

Todo el estado C09 vive en memoria. No hay DAO, Room, archivo, DTO wire,
endpoint, publicación ni upload. Los perfiles minimizan lecturas sensibles y
las representaciones textuales redactan SSID/BSSID. Los fallos sólo contienen
operación, motivo cerrado y tiempos.

No existe paridad exacta con Windows/Linux: una lectura Android legacy es
aproximada y device-scoped; `WifiInfo` del callback es network-scoped; captura
IP, radiotap/802.11 y telemetría de infraestructura son no comparables.

## Evidencia automatizada y validación física pendiente

Los tests de dominio cubren invariantes, null/zero/false, identidades, copia
defensiva, tiempo y scopes. Los tests de mapper cubren profiles, transportes,
VPN, capabilities, API policy, legacy/network-scoped, permisos, location,
KPIs, derivaciones y sentinels legacy individuales/combinados. Robolectric
valida lifecycle determinista sin `sleep`, callbacks tardíos, fast switching,
interrupción/cancelación, entrega ordenada por listener, operaciones externas
sin monitor y start/stop/close concurrentes con latches. Los tests de app y
manifest verifican composición lazy, permisos exactos y ausencia de componentes.
La suite específica del facade cubre los siete límites de cancelación por
identidad, `Error` por identidad, degradaciones ordinarias, casos A/B/C,
callbacks básico/location-aware, fallos de notificación, secundarios de
cleanup, self-suppression y generaciones antiguas. La suite del observer agrega
la reconciliación directa de la frontera tipada y su aislamiento por
generación; ausencia total de tiempo válido; reutilización exacta del último
tiempo y del snapshot; causalidad entre mapping, unregister, dispatcher, reloj
y listener; interrupción; múltiples waiters; reinicio; y la matriz completa de
15 tokens anti-reflection.

Evidencia automatizada ejecutada:

- suites C09 focalizadas debug y release: 112/112 por variante, sin
  failures/errors/skips —29 facade, 70 observer y 13 mapper—;
- suites completas de `:core:platform`: 162/162 por variante, sin
  failures/errors/skips;
- `:core:platform:lintDebug`: 0 issues;
- la matriz Android completa y el task agregado `test` no se repitieron tras
  esta corrección focalizada; su último baseline previo fue 1123
  ejecuciones en la matriz y 642 tests por composición debug/release, antes de
  agregar las tres regresiones actuales;
- en ese baseline previo, `:app:lintDebug` tuvo 0 errores y 12 warnings ajenos
  a C09 —versiones de AGP/dependencias e icono—;
- `:app:processDebugMainManifest`, `:app:processReleaseMainManifest` y
  `:app:assembleDebug`: exitosos;
- `scripts/validate_repository.py`: exitoso;
- `git diff --check`: exitoso.

La campaña secuencial con `--rerun-tasks` registró:

| Campaña | Iteraciones | PASS | FAIL | Timeout | Duración total |
|---|---:|---:|---:|---:|---:|
| Tres casos deterministas por ejecución: waiter confirmado, close ganador e interrupción del waiter | 50 | 50 | 0 | 0 | 518,978 s |
| `AndroidConnectivityObserverTest` debug | 20 | 20 | 0 | 0 | 284,678 s |
| `AndroidConnectivityObserverTest` release | 20 | 20 | 0 | 0 | 287,090 s |
| `:core:platform:testDebugUnitTest` | 5 | 5 | 0 | 0 | 74,252 s |
| `:core:platform:testReleaseUnitTest` | 5 | 5 | 0 | 0 | 72,739 s |

Cada una de las 50 ejecuciones de la primera fila incluyó los tres casos, para
150 casos deterministas ejecutados. En todas las campañas se conservaron un
solo unregister, un solo cierre del dispatcher, sesión ausente, estado final
contractual y terminación de los executors; no quedaron threads de prueba
retenidos. El gate anti-reflection, su matriz normativa independiente de 15
tokens y sus omisiones/duplicado/extra/vacío permanecieron verdes.

Un intento de agrupar las repeticiones debug 4–6 de la clase completa superó
el límite de 60 segundos de la consola. No fue un timeout JUnit ni se
contabilizó como iteración: las tres posiciones se repitieron desde cero en
lotes acotados y quedaron incluidas en las 20 ejecuciones confirmadas de la
tabla. El postflight no encontró ningún `Gradle Test Executor`; sólo
permanecieron los daemons estándar de Gradle y compilación Kotlin.

Docker no se utilizó en esta corrección.

Robolectric no constituye validación física. La variante API 31 adicional no
está disponible en el cache offline y queda `NOT RUN`. Emuladores, teléfono/CPE,
hardware real, cambios Wi-Fi/cellular, grants reales, toggle de ubicación,
fabricantes/OEM, process death real, Doze/background y comportamiento radio
quedan `NOT RUN` para C12.

## Rollback

El rollback de C09 consiste en retirar los nueve archivos nuevos y revertir
únicamente los nueve archivos modificados del inventario C09, incluido el gate
Gradle. No requiere migración, limpieza de datos, revocación de endpoint ni
regeneración de contratos porque C09 no persiste ni transmite estado. C08, Room
v1/v2/v3, contratos, locks y metadata deben permanecer byte-identical.

## Limitaciones

- La app todavía no solicita el permiso peligroso ni ofrece UI para seleccionar
  el perfil autorizado.
- No hay ejecución background, WorkManager, presence ni Foreground Service.
- No hay scan, control de red, probes, tráfico, throughput o tareas remotas.
- Channel width, MLO, per-link metrics y captura 802.11 no se inventan.
- La lectura legacy API 29–30 no prueba la red por defecto.
- La asociación debajo de una VPN no es observable de forma suficiente.
- No existe persistencia, envío o correlación entre planos.
- La matriz física API 29/35/36.0/36.1 y OEM permanece pendiente.
