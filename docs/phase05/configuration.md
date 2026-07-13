# Configuración desktop

El archivo es TOML estricto y sólo admite la sección `[agent]`. Campos o
secciones desconocidos impiden iniciar. La precedencia es:

1. defaults seguros;
2. TOML;
3. variables `WTO_AGENT_*` documentadas por el loader;
4. overrides explícitos del composition root.

La plantilla está en `agents/desktop/wto-agent.example.toml`. Fuera de
development/test, `server_url` debe usar HTTPS. El CA bundle es opcional y
permite confiar en la CA privada del laboratorio sin desactivar verificación.

TOML nunca admite enrollment tokens, credentials, Authorization, cookies,
nonces ni material de claves. `enroll` obtiene el token únicamente mediante
prompt oculto, stdin explícito o una variable de entorno elegida por el
operador. No existe argumento visible `--token`.

`allow_in_memory_secret_store` sólo es válido con `environment` igual a
`development` o `test`. En producción la combinación se rechaza al validar la
configuración.

En Windows, `windows_inventory_timeout_seconds` limita el proceso allowlisted de
PowerShell completo. Su valor por defecto productivo es 30 segundos, admite
entre 10 y 120 segundos por compatibilidad de configuración y también puede
configurarse con `WTO_AGENT_WINDOWS_INVENTORY_TIMEOUT_SECONDS`. El baseline de
producción y CI debe conservar 30 segundos: este límite externo es sólo la
última barrera de seguridad y no se aumenta para compensar un proveedor lento o
bloqueado.

El adapter deriva de ese valor local el entorno interno
`WTO_INVENTORY_OUTER_TIMEOUT_MILLISECONDS`; no acepta ese dato desde el servidor
ni lo expone como configuración adicional. El guard interno también exige que el
presupuesto completo quepa en ese límite externo. Si un valor compatible pero
menor no alcanza, aborta antes de liberar la barrera y devuelve fail-soft.

El proceso tiene además límites internos no configurables desde TOML. Lanza
siete procesos `powershell.exe` explícitos con comandos locales fijos; no usa
`Start-Job`, `JobRepository` ni `StopAsync`. Los presupuestos son:
`Win32_PnPSignedDriver` 8 s, `Get-NetAdapter` 8 s,
`Get-NetAdapterStatistics` 5 s, `Get-NetIPConfiguration` 10 s,
`Get-NetIPAddress` 5 s, `Get-NetRoute` 5 s y
`Get-DnsClientServerAddress` 5 s.

Cada worker publica primero `PID|creationFileTime`, vacía stdout, señala un
evento ready y espera un evento start separado. El coordinador valida el marker
por el handle estable obtenido del proceso concreto, le asigna un Job Object
kill-on-close y recién entonces libera la barrera. PID es sólo metadata: nunca
se reabre con permiso de terminación. Si falta un marker dentro de los 5 segundos
de startup, el worker se termina sin entrar al provider.

Los siete presupuestos comienzan desde el mismo timestamp de release. Antes de
liberar la barrera, el coordinador comprueba que el budget máximo de 10 segundos,
el reap compartido de 3 segundos y el cierre y espera final de 1 segundo caben
completos en la fase de providers de 20 segundos. Esos límites más una reserva
de 1 segundo para ensamblar inventario deben caber en la ventana interna de
planificación de 26 segundos. El guard conserva además 1 segundo de margen antes del watchdog
externo. Si no caben, no ejecuta providers y devuelve resultado fail-soft. Los streams se
leen de forma asíncrona y siempre se observan y disponen durante cleanup. El Job
Object externo del process runner conserva la responsabilidad de última barrera dura
a 30 segundos.

Ese timeout externo se convierte en un deadline absoluto antes de iniciar el
spawn: creación suspendida, validación, asignación al Job Object, `ResumeThread`
y ejecución consumen el mismo presupuesto. Ante fallo, timeout o cancelación,
el runner dispone de una gracia de cleanup máxima de 5 segundos y reserva sus
últimos 100 ms para cerrar forzosamente Job, pipes, transport y handles y
drenar las tareas controladas.

`WTO_INVENTORY_DIAGNOSTICS=1` no es una clave TOML ni modifica contratos. Es un
switch operativo explícito para diagnóstico del proceso: registra nombre,
estado, duración, presupuesto, cantidad de elementos, `worker_state` y método de
terminación de cada proveedor, más el resultado del cleanup, exclusivamente en
stderr. Stdout conserva siempre un único documento JSON estricto. El campo
compatibilidad `jobs_remaining` debe ser siempre cero porque no hay jobs
PowerShell; `processes_remaining` cuenta cualquier proceso, stream o lifecycle
cuya disposición no pudo verificarse.
