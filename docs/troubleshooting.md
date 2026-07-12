# Troubleshooting de desarrollo

## El puerto 8080 está ocupado

Defina otro puerto sólo para el reverse proxy:

```powershell
$env:WTO_HTTP_PORT = '18080'
docker compose up -d --wait
```

PostgreSQL, Redis, backend y frontend no deben recibir mapeos de puertos como
solución. Use `docker compose exec` para diagnósticos internos.

## Un servicio no pasa health check

Inspeccione estado y logs sin imprimir la configuración renderizada:

```powershell
docker compose ps
docker compose logs --tail 200 backend worker postgres redis artifact-store simulated-agent
```

`/health/live` sólo valida el proceso backend. `/health/ready` devuelve 503 si
PostgreSQL, Redis o el artifact store fallan, pero omite DSNs, rutas y detalles
de excepciones.

## Docker Desktop o WSL2 no responden

Compruebe que Docker Desktop use contenedores Linux y que la integración WSL2
esté habilitada. Reiniciar Docker no requiere eliminar volúmenes. Use el reset
destructivo únicamente si los datos locales pueden descartarse.

## Migración fallida

Ejecute:

```powershell
./scripts/dev.ps1 migrate
```

La revisión inicial es una baseline vacía y no crea modelos definitivos. Si la
base local es descartable, consulte el procedimiento de rollback antes de
eliminar volúmenes.

## El agente simulado no aparece

Revise `docker compose logs simulated-agent backend`. El agente debe publicar
heartbeats desde la red interna y el entorno debe ser `development` o `demo`.
En `production`, los endpoints demo responden 404 por diseño.

## Certificados

La Fase 02 local usa HTTP y no instala una CA. No exponga este deployment fuera
del host de desarrollo. TLS y el lifecycle de credenciales se incorporarán en
fases posteriores.
