# Contraseñas, tokens, CSRF y proxy

## Contraseñas

Argon2id v19 usa inicialmente 65536 KiB, tres iteraciones, paralelismo 1, hash
de 32 bytes y salt aleatorio de 16 bytes. Configuración puede elevar el costo,
pero los settings rechazan mínimos inferiores. Después de un login válido se
ejecuta `check_needs_rehash()` y se reemplaza el hash dentro de la transacción.
Un usuario inexistente verifica un hash dummy. No se registra contraseña ni hash.

Las contraseñas tienen mínimo 12 caracteres, máximo 1024 bytes UTF-8 y no se
truncan. El administrador bootstrap inicia con `must_change_password=true`.

## Access token

JWT HS256 dura 10 minutos. La clave contiene al menos 256 bits y la allowlist es
fija. Se validan firma, algoritmo, `typ=at+jwt`, issuer, audience, subject,
`iat`, `nbf`, `exp`, `jti`, `token_type`, `sid` y `auth_version`. No contiene
roles ni permisos y no se almacena completo. Clientes deben mantenerlo sólo en
memoria; no usar localStorage, sessionStorage, IndexedDB ni cookies accesibles
por JavaScript.

## Refresh y revocación

El refresh es opaco, aleatorio de 256 bits y sólo se persiste su SHA-256. Viaja
en cookie HttpOnly, SameSite Strict, Secure fuera de development, sin Domain y
con path `/api/internal/v1/auth`. Cada uso bloquea la fila con `FOR UPDATE`,
consume el token y crea su replacement en una transacción. Reuse revoca toda la
familia. Expiración absoluta: 30 días; inactividad: 7 días.

Logout revoca la familia actual. Logout global, cambio de contraseña y
desactivación incrementan `auth_version` y revocan todas las sesiones.
PostgreSQL es la única autoridad; Redis nunca decide validez.

## CSRF y proxy

Refresh, logout y cambio de contraseña comparan `Origin` con
`WTO_ALLOWED_ORIGIN`; `Referer` es sólo fallback. Ausencia o mismatch falla
cerrado. No se habilita CORS permisivo y frontend/API permanecen same-origin.

Nginx sobrescribe `X-Real-IP` y `X-Forwarded-For`. El backend sólo acepta
`X-Real-IP` si el peer pertenece a `WTO_TRUSTED_PROXY_CIDRS`; en otro caso usa
la IP del socket e ignora headers suministrados por el cliente.

## Rate limit

Redis incrementa atómicamente ventanas por fingerprint HMAC de IP efectiva e
identificador normalizado. Las claves HMAC no se reutilizan. No hay lockout
persistente. Redis inaccesible produce 503; exceso produce 429 genérico.
