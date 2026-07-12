# Plugins desktop

Fase 05 registra únicamente `protocol.contract_check`, un plugin sin efectos,
red, procesos ni artifacts. Sirve para validar el TaskRunner y sus fronteras de
persistencia.

El `PluginRegistry` se construye explícitamente en el composition root. La
allowlist efectiva es la intersección entre plugins compilados y configuración
local; la configuración sólo puede restringir. No se usa `eval`, importación
dinámica, entry points ni nombres de módulos recibidos del servidor.

Cada plugin declara task type y versión, provider, método, modelo Pydantic de
parámetros, timeout máximo y command IDs requeridos. Antes del claim el runner
rechaza plugins desconocidos, parámetros inválidos y tareas expiradas.

`cleanup` debe ser idempotente. SQLite registra por separado cuándo fue
solicitado, cuántos intentos hubo y cuándo terminó. La firma, distribución y
revocación de paquetes externos continúa diferida según ADR-0014.
