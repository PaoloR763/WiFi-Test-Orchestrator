# Recovery, upgrade y rollback

SQLite 0002 agrega sólo el journal Windows. Intent se persiste con `BEGIN IMMEDIATE` antes del
efecto. Tras crash, connect/disconnect reconcilian el estado real; rollback reconecta sólo un
perfil anterior todavía allowlisted. No se guardan XML, passwords ni enrollment tokens.

Las migraciones siguen forward-only, con checksum, backup API y quick_check. Volver a Fase 05
requiere detener el servicio y restaurar el backup schema 1; el binario anterior debe rechazar
schema 2.

Upgrade instala side-by-side, detiene, crea backup verificado, registra el nuevo ImagePath,
inicia y consulta health. Si falla, rollback exige confirmación, bundle anterior y backup válido.
