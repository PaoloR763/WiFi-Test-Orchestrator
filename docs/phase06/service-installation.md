# Instalación del Windows Service

El servicio pywin32 usa `NT AUTHORITY\LocalService`, delayed automatic start, service SID y
recovery restart escalonado sin reboot. Implementa start, stop, pause, resume, shutdown y power
events. Sleep/resume invalida observaciones antes del ciclo siguiente.

Binarios viven bajo Program Files; configuración, estado, logs y artifacts se separan bajo
ProgramData. SYSTEM y Administrators conservan control; el service SID recibe read/execute sobre
binarios/config y modify sólo sobre estado, logs y artifacts. `ImagePath` usa comillas y se
revalida desde SCM.

Enrollment del servicio usa un named pipe local con ACL SYSTEM/Administrators/service SID. El
pipe acepta únicamente `operation=enroll` 1.0.0, una operación acotada por conexión. El servicio
escribe Credential Manager bajo su propio token. No existe listener TCP.

Referencias primarias: [cuenta LocalService](https://learn.microsoft.com/windows/win32/services/localservice-account),
[delayed automatic start](https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info)
y [CredWrite](https://learn.microsoft.com/windows/win32/api/wincred/nf-wincred-credwritew).
