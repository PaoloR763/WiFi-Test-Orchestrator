# Doctor y troubleshooting

`wto-agent doctor` valida TLS, inventario contractual empaquetado, SQLite,
SecretStore y ServiceManager. `--json` produce checks estructurados con estados
`OK`, `DEGRADED` o `BLOCKED`.

Casos frecuentes:

- `secret_store BLOCKED` en Linux: iniciar dentro de una sesión con Secret
  Service disponible y colección desbloqueada;
- SQLite bloqueada: confirmar ownership del state dir y que no exista otra
  instancia escribiendo durante más que el `busy_timeout`;
- checksum de migración: no editar migraciones publicadas; restaurar código y
  backup coherentes;
- manifest o heartbeat pendiente: el runtime reenvía exactamente el payload
  persistido; no borrar manualmente la fila;
- credential rechazada: el agente marca la identidad local revocada y no prueba
  secretos anteriores fuera de un cutover de rotación en curso.

No adjuntar la base, environment o logs sin aplicar la política del laboratorio.
Aunque SQLite no contiene secrets, sí contiene identidad y metadata operativa.
