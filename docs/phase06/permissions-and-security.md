# Permisos y seguridad

- No hay shell, cmdlet dinámico ni argumentos libres.
- DLLs del sistema se cargan por path canónico; procesos usan executable absoluto.
- Output, timeout y process tree están limitados; Windows usa Job Object.
- Paths de servicio se resuelven, quotean y validan; ACL impide que LocalService reemplace binarios.
- SSID, BSSID, tokens, credentials, Authorization, cookies y nonces se redactan en logs.
- Credential Manager nunca tiene fallback a TOML, SQLite o archivo.
- NetworkController exige elevación administrativa, allowlist local y confirmación; las
  operaciones con efecto agregan idempotency key y journal previo.
- Captura sigue opt-in y no ejecutable.

La verificación hash reduce TOCTOU de herramientas, pero un executable externo mutable no se
considerará apto para comandos productivos futuros sin ACL y firma/publisher validados.
