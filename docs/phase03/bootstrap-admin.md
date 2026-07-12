# Runbook de bootstrap

1. Genere `.env` con `scripts/generate-env.ps1` o `scripts/generate-env.sh`.
2. Inicie servicios y aplique migraciones.
3. Ejecute `./scripts/dev.ps1 seed` o `sh scripts/dev.sh seed`.
4. Ejecute `./scripts/bootstrap-admin.ps1 -Username admin` o
   `sh scripts/bootstrap-admin.sh admin`.
5. Ingrese la contraseña por prompt oculto. Nunca se acepta `--password`.
6. Inicie sesión y cambie inmediatamente la contraseña inicial.

También existe `--password-env` con `WTO_BOOTSTRAP_ADMIN_PASSWORD` para
automatización controlada; la variable nunca se registra. Si el mismo admin ya
existe activo, bootstrap es no-op auditado. Un username incompatible o un
administrador diferente existente produce error. Advisory locking protege
ejecuciones concurrentes.
