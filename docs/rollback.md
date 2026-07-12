# Rollback de desarrollo

Para Fase 03 consulte también
[`docs/phase03/migrations-and-rollback.md`](phase03/migrations-and-rollback.md).
Para Fase 04 consulte
[`docs/phase04/operations.md`](phase04/operations.md).
El rollback de aplicación debe conservar inicialmente el schema aditivo. El
downgrade a la baseline vacía destruye usuarios, sesiones y auditoría.

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
