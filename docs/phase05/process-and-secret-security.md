# ProcessRunner y SecretStore

## ProcessRunner

El registry productivo de comandos está vacío. Una invocación futura deberá
usar un `command_id` local que resuelva a `CommandSpec`; el executable es
absoluto y argv se construye desde un modelo validado. Se usa
`create_subprocess_exec`, nunca shell. Cwd, environment, timeout y tamaño de
stdout/stderr son acotados.

Linux crea un process group y termina el grupo. Windows crea un Job Object con
`KILL_ON_JOB_CLOSE`. El plugin built-in no usa ProcessRunner.

## SecretStore

Windows usa Credential Manager a través del adapter Windows-only. Linux usa
Secret Service mediante el adapter Linux-only. No existe fallback persistente
a SQLite, TOML, JSON, environment generado ni archivos de texto.

Si el backend seguro no está disponible, `enroll` y `run` fallan cerrados y
`doctor` informa `BLOCKED` sin datos sensibles. En Linux headless suele faltar
un session bus o una colección desbloqueada; Fase 05 no instala ni desbloquea
automáticamente Secret Service. La integración con credenciales de systemd se
difiere junto al ServiceManager real.

InMemorySecretStore sólo se admite en development/test explícito. Los logs
redactan machine secrets, Authorization, cookies, nonces y campos identificados
como secretos. Las excepciones sólo se serializan por nombre de clase.
