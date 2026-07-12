# Rollback de la Fase 02

## Detener sin perder datos

```powershell
./scripts/dev.ps1 down
```

```sh
sh scripts/dev.sh down
```

Esto elimina contenedores y redes del proyecto, pero conserva los volúmenes
nombrados de PostgreSQL, Redis y artefactos.

## Volver a imágenes previas

Cambie al commit conocido mediante el flujo Git del equipo y reconstruya con
`docker compose build`. No mezcle imágenes antiguas con migraciones nuevas sin
revisar primero la compatibilidad de Alembic.

## Reset destructivo

Sólo para datos locales descartables:

```powershell
./scripts/dev.ps1 reset -ConfirmReset
```

```sh
sh scripts/dev.sh reset --confirm
```

El reset elimina los tres volúmenes nombrados. No se ejecuta desde `down` ni
como efecto secundario de otra acción. Antes de usarlo en un entorno compartido
se requiere un backup y una prueba de restauración; esos procedimientos están
fuera del alcance de Fase 02.
