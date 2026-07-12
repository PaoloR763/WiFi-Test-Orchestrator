# WiFi Test Orchestrator

Plataforma distribuida para automatizar, ejecutar, observar y administrar
pruebas Wi-Fi en laboratorios, pilotos y redes autorizadas.

## Estado del proyecto

El proyecto se encuentra en la Fase 04. Incluye un entorno local ejecutable con
reverse proxy, frontend, backend, worker, PostgreSQL, Redis, artifact store
filesystem, agente simulado outbound-only, autenticación local, sesiones con
rotación, RBAC humano y auditoría append-only para aplicación/rol runtime. Los
contratos OpenAPI/JSON Schema normativos, enrolamiento individual, rotación y
revocación de credentials, capability manifests y presence desktop/mobile.

Baselines aprobados:

| Superficie | Versión inicial |
|---|---|
| Producto | `0.1.0` |
| API | `v1` |
| JSON Schemas | `1.0.0` |
| Agent Protocol | `1.0.0` |
| Plugin API | `1.0.0` |

La documentación arquitectónica canónica se encuentra en
[docs/architecture](docs/architecture/README.md). Los ADRs especializan las
reglas globales de `AGENTS.md` sin contradecirlas.

## Objetivos principales

- Administrar dispositivos y agentes de prueba.
- Recopilar telemetría Wi-Fi y del sistema operativo.
- Ejecutar pruebas de conectividad, latencia, throughput y estabilidad.
- Generar tráfico controlado mediante providers intercambiables.
- Gestionar casos, suites, planes y campañas de prueba.
- Correlacionar métricas del endpoint con APs, gateways y controladores.
- Almacenar logs, capturas, métricas y evidencias.
- Comparar resultados entre modelos, configuraciones y firmware.
- Generar dashboards y reportes técnicos.

## Arquitectura prevista

La solución contempla:

- Servidor central portable.
- Interfaz web.
- Motor de orquestación y cola persistente.
- Motor de pruebas y tráfico extensible.
- Agentes Windows y Linux.
- Aplicaciones agente Android e iOS.
- Agente simulado.
- Traffic Nodes y Capture Nodes especializados.
- Adaptadores para infraestructura de red.
- Campañas, resultados, telemetría, artefactos y reportes.

Las responsabilidades se separan entre control plane, data plane, telemetry
plane, artifact plane e integration plane.

## Servidor

El desarrollo inicial se realiza en Windows 11 mediante Docker Desktop y WSL2.
Los servicios del servidor se ejecutarán como contenedores Linux OCI y no
dependerán funcionalmente de rutas, servicios ni APIs del host Windows.

La portabilidad futura incluye Linux, macOS y entornos cloud sin cambiar el
dominio ni los contratos.

El entorno mínimo se inicia sin profiles adicionales:

```sh
docker compose up -d --wait
```

La UI queda en `http://localhost:8080`. Consulte la
[guía de desarrollo](docs/development.md), el
[mapa del repositorio](docs/repository-map.md),
[troubleshooting](docs/troubleshooting.md) y [rollback](docs/rollback.md).

Antes del primer inicio genere secretos locales:

```powershell
./scripts/generate-env.ps1
```

La referencia de identidad está en [docs/phase03](docs/phase03/README.md).

La referencia normativa de Fase 04 está en
[docs/phase04](docs/phase04/README.md).

## Agentes y capabilities

La arquitectura contempla Windows, Linux, Android e iOS. Cada agente publicará
un Capability Manifest multidimensional. El servidor no asumirá paridad entre
plataformas ni reducirá soporte, implementación, permisos, interacción y
background a un único estado.

Toda afirmación depende de versión del sistema operativo, hardware, driver,
permisos, entitlements y APIs disponibles.

La primera implementación funcional priorizará:

1. Servidor.
2. Frontend.
3. Agente simulado.
4. Agente Windows.
5. Agente Linux.

Android e iOS estarán contemplados por los contratos desde el inicio, con
implementación posterior y respetando sus lifecycles.

## Generación de tráfico

El motor será capability-driven. `traffic.tcp.throughput` y
`traffic.udp.throughput` describen funciones; iperf3 será un provider/plugin:

```yaml
provider_id: traffic-provider-iperf3
implements:
  - traffic.tcp.throughput
  - traffic.udp.throughput
```

Toda prueba de tráfico tendrá límites efectivos concretos y un destino
autorizado mediante una reserva emitida por el servidor. Un límite solicitado
`null` significa heredar política, nunca ejecución ilimitada.

## Documentación

- `docs/architecture/`: arquitectura normativa de Fase 01, Mermaid, ADRs,
  threat model y capability matrix.
- `prompts/`: prompts de desarrollo divididos por fases y ejemplos
  ilustrativos no normativos.
- `scripts/`: scripts equivalentes de desarrollo, validación y mantenimiento.
- `AGENTS.md`: reglas permanentes y autoridad normativa global.
- `CHANGELOG.md`: cambios del producto.

Los PDF y DOCX existentes se conservan como archivos del repositorio; la
arquitectura canónica de esta fase es la documentación Markdown bajo
`docs/architecture/`.

## Seguridad y uso autorizado

La plataforma se utilizará exclusivamente sobre dispositivos, servidores,
redes y laboratorios autorizados.

No proporcionará una consola remota arbitraria ni permitirá comandos fuera de
plugins y acciones allowlisted. Agentes usan HTTPS outbound-only, credenciales
individuales rotables, leases e idempotencia. FCM y APNs son avisos; las tareas
se recuperan por HTTPS.

## Roadmap

El orden detallado se mantiene en
[prompts/PROMPT_INDEX.md](prompts/PROMPT_INDEX.md). Las primeras etapas son:

1. Arquitectura, ADRs y modelo de amenazas.
2. Monorepo e infraestructura local.
3. Backend, base de datos, autenticación y RBAC.
4. Contratos, capabilities y enrolamiento.
5. Agentes y orquestación multiplataforma.
6. Probes, tráfico, telemetría, campañas y artefactos.
7. Seguridad, observabilidad, packaging y validación end-to-end.
