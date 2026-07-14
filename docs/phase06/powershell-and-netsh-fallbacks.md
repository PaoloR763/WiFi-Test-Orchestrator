# PowerShell y netsh

El script empaquetado `network_inventory.ps1` proyecta propiedades primitivas y emite un único
JSON UTF-8 sin BOM. Usa `-NoLogo -NoProfile -NonInteractive`, arrays explícitos y
`ConvertTo-Json -Compress -Depth 8`. Windows PowerShell 5.1 es baseline y PowerShell 7 es matriz
adicional. No se aceptan cmdlets, scripts o parámetros del servidor.

Las siete fuentes se declaran mediante consultas fijas y localmente allowlisted;
no hay scripts descargados, evaluación dinámica ni parámetros del servidor. El
script crea siete procesos `powershell.exe` explícitos con ejecutable, plantilla
y consulta fijados localmente. No usa `Start-Job`, `JobRepository`, `StopAsync`
ni cmdlets para ocultar jobs. Cada fuente se consulta una sola vez antes de
indexar resultados por interface index o device ID.

| Fuente | Timeout individual |
| --- | ---: |
| `Win32_PnPSignedDriver` | 8 s |
| `Get-NetAdapter` | 8 s |
| `Get-NetAdapterStatistics` | 5 s |
| `Get-NetIPConfiguration` | 10 s |
| `Get-NetIPAddress` | 5 s |
| `Get-NetRoute` | 5 s |
| `Get-DnsClientServerAddress` | 5 s |

Cada worker escribe como primera línea `PID|creationFileTime`, vacía stdout,
señala su `ReadyEvent` y espera un `StartEvent` separado. El coordinador abre el
worker como un `System.Diagnostics.Process`, duplica y conserva su handle,
valida por ese mismo handle PID, creation time e imagen, y crea el Job Object
del provider antes de liberar el start. `ReadyEvent` observado y marker leído,
parseado y validado son dos condiciones independientes: ninguna por sí sola
libera la barrera. Si ready llega primero, el coordinador continúa consumiendo
el pipe hasta el deadline de startup de 5 segundos. Un worker cuyo marker no fue
validado al vencer ese deadline nunca entra al provider y se termina mediante el
handle estable retenido.

PID es sólo metadata. No existe reapertura por PID con `PROCESS_TERMINATE`; la
terminación usa exclusivamente el handle estable retenido desde el worker
original. Cualquier handle abierto por PID durante reap solicita sólo query y
synchronize, se valida con `IsProcessInJob` y sirve únicamente para esperar. Al
vencer un budget, `TerminateProcess` actúa sobre el handle original y
`TerminateJobObject` contiene también los descendientes.

Todos los providers liberados comparten un timestamp de inicio, por lo que sus
budgets de 8/8/5/10/5/5/5 segundos se conservan íntegros y corren en paralelo.
El deadline de startup es independiente de esos budgets: los budgets comienzan
únicamente después de que todos los workers elegibles cumplieron ambas
condiciones y se liberaron juntos sus `StartEvent`.
Antes del release, un guard comprueba que el máximo de 10 segundos, los 3
segundos de reap y el segundo final de close-and-wait caben en la fase de
providers de 20 segundos. Esos límites más una reserva de 1 segundo para
ensamblado deben caber en la ventana interna de planificación de 26 segundos del
coordinador. La fase de
providers comienza después de compilar el soporte nativo y crear los workers,
antes del startup y los markers. El guard también reserva 1 segundo antes del
watchdog externo. Si no caben, no
libera ningún provider y devuelve inventario fail-soft.

La salida posterior al marker se recolecta con `ReadToEndAsync`, se decodifica
como Base64 de XML `PSSerializer` UTF-16 y se observa y dispone junto con
stderr. El stderr de un worker nunca se reenvía porque puede contener datos del
host. El cleanup usa 3 segundos compartidos para terminar y observar procesos,
árboles y
streams, seguidos por 1 segundo final para cerrar Job Objects y esperar handles
estables. No hay jobs PowerShell, runspaces administrados ni objetos que se
desregistren para aparentar cleanup.

El timeout externo de `windows_inventory_timeout_seconds` permanece en 30
segundos como última barrera de seguridad. El process runner crea al coordinador
con `CREATE_SUSPENDED`, lo asigna mediante el handle original de CreateProcess a
un Job Object kill-on-close y sólo después reanuda el thread inicial. El deadline
absoluto de la solicitud empieza antes del spawn e incluye creación, validación,
asignación, resume y ejecución. Todo fallo posterior a crear recursos entra a un
cleanup transaccional de hasta 5 segundos, con los últimos 100 ms reservados
para force-close y drenaje de tareas. Un `ProcessContext` retenido por token
opaco e identidad del objeto proceso posee Job y thread; `process.pid` no
participa del ownership.

El adapter comunica el timeout local validado mediante la variable interna
`WTO_INVENTORY_OUTER_TIMEOUT_MILLISECONDS`. El release guard incluye ese valor:
si la configuración permitida es menor que el presupuesto completo restante,
aborta antes de abrir los gates. Esta variable no es entrada del servidor ni una
nueva opción operativa; el baseline de producción y CI continúa en 30 segundos.

La consulta de `Win32_PnPSignedDriver` proyecta sólo cinco propiedades y conserva
también `OperationTimeoutSec=8` como límite cooperativo de CIM. La terminación
efectiva, sin embargo, depende del handle estable y del Job Object individual,
no del `try/catch`, del stop cooperativo ni de CIM. Si drivers
vence, `manufacturer`, `model`, `driver_provider` y las versiones que dependan
exclusivamente de esa fuente quedan nulos.

El comportamiento es fail-soft para errores y timeouts. Si falla adaptadores,
el array `adapters` queda vacío; si falla drivers, quedan nulos sus valores
derivados. Si falla estadísticas, configuración IP, direcciones, rutas o DNS,
el JSON se sigue generando, la colección de esa fuente queda vacía, sus valores
derivados quedan nulos y el campo `*_available` existente queda en `false` para
cada adaptador ensamblado. Listas vacías y valores nulos no se reinterpretan
como mediciones. El schema y sus claves no cambian.

Con `WTO_INVENTORY_DIAGNOSTICS=1`, el script escribe una línea por proveedor con
`provider`, `status`, `elapsed_ms`, `timeout_ms`, `items`, `termination` y
`worker_state`, seguida
por una línea de cleanup con `jobs_remaining`, `processes_remaining` y
`elapsed_ms`. Este modo sólo escribe en stderr; stdout continúa siendo
exactamente un documento JSON UTF-8 estricto. En CI debe capturarse stderr por
separado para identificar el proveedor que excedió su presupuesto, confirmar
`termination=process_handle` y comprobar
`jobs_remaining=0 processes_remaining=0`. `jobs_remaining` se conserva en cero
por compatibilidad del diagnóstico: no representa un repositorio. En cambio,
`processes_remaining` también queda distinto de cero si no se verificó el cierre
de un stream, un proceso o su lifecycle, aunque el objeto ya no sea visible.

El parser Pydantic es cerrado. Ruido, truncamiento, encoding inválido, exceso de salida o JSON
corrupto rechazan esa fuente.

`netsh wlan show interfaces` es read-only y último fallback. Los parsers en-US, es-AR y es-ES
aceptan UTF-8, Windows-1252/OEM, Unicode, campos ausentes y labels desconocidos. Sus valores usan
confidence menor. Nunca se usa tras un privacy access denied ni para modificar red.
