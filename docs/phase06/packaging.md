# Packaging preliminar

Se mantienen wheel y contratos derivados. Windows agrega PyInstaller onedir, spec versionado,
bundle manifest SHA-256 y scripts build/install/uninstall/upgrade/rollback. Las versiones se
instalan side-by-side y el upgrade crea un backup SQLite verificado antes de cambiar el servicio.

No se afirma reproducibilidad byte-for-byte: el manifest lo declara falso hasta comparar dos
builds limpios. No se incluyen certificados, firma simulada, MSI/MSIX/WiX ni auto-update. Esas
decisiones pertenecen a Fase 24.

Uninstall conserva ProgramData e identidad por defecto. Purge exige confirmación y un control SCM
fijo para que LocalService elimine su Credential Manager; si no confirma éxito, uninstall aborta.

## Confinamiento de rutas

En modo productivo los scripts aceptan exclusivamente
`%ProgramFiles%\WiFi Test Orchestrator\Agent` como `InstallRoot` y
`%ProgramData%\WiFiTestOrchestrator\Agent` como `DataRoot`. Los overrides, paths relativos,
traversal, raíces de volumen y reparse points fallan antes de copiar, reemplazar, restaurar o
borrar. Config queda bajo `DataRoot\config`, estado y backups bajo `DataRoot\state`, y cada bundle
queda bajo `InstallRoot\versions\<semver>`.

`-TestMode` requiere `-WorkRoot` explícito. `InstallRoot` y `DataRoot` deben ser directorios
distintos y descendientes estrictos de ese root temporal. El uninstall de prueba conserva
`DataRoot` y solo elimina el `InstallRoot` nuevamente validado. Los backups de upgrade usan
`agent.sqlite3.pre-upgrade-<semver>.bak`; el backup `agent.sqlite3.test-backup` se admite únicamente
en TestMode. Rollback rechaza archivos externos, reparse points y versiones no SemVer antes de
invocar la verificación/restauración SQLite existente.
