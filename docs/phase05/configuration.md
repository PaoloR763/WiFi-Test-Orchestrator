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
PowerShell completo. Su valor por defecto es 30 segundos, admite entre 10 y 120
segundos y también puede configurarse con
`WTO_AGENT_WINDOWS_INVENTORY_TIMEOUT_SECONDS`. No desactiva el límite interno de
8 segundos de la consulta opcional de drivers firmados.
