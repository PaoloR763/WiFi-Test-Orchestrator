# WiFi Test Orchestrator

Plataforma distribuida para automatizar, ejecutar, observar y administrar
pruebas Wi-Fi en laboratorios, pilotos y redes autorizadas.

## Estado del proyecto

El proyecto se encuentra en su etapa inicial de arquitectura, definición
de contratos y preparación del entorno de desarrollo.

Todavía no existe una versión funcional del producto.

## Objetivos principales

- Administrar dispositivos y agentes de prueba.
- Recopilar telemetría Wi-Fi y del sistema operativo.
- Ejecutar pruebas de conectividad, latencia, throughput y estabilidad.
- Generar tráfico controlado mediante proveedores intercambiables.
- Gestionar casos, suites, planes y campañas de prueba.
- Correlacionar métricas del endpoint con APs, gateways y controladores.
- Almacenar logs, capturas, métricas y evidencias.
- Comparar resultados entre modelos, configuraciones y firmware.
- Generar dashboards y reportes técnicos.

## Arquitectura prevista

La solución estará compuesta por:

- Servidor central.
- Interfaz web.
- Motor de orquestación.
- Motor de pruebas.
- Motor de generación de tráfico.
- Agente Windows.
- Agente Linux.
- Aplicación agente Android.
- Aplicación agente iOS.
- Capture Nodes especializados.
- Adaptadores para infraestructura de red.
- Sistema de campañas, resultados, artefactos y reportes.

## Servidor

El despliegue inicial estará orientado a Windows mediante:

- Windows 11.
- Docker Desktop.
- WSL2.
- Contenedores Linux.

Los servicios deben mantenerse desacoplados del sistema operativo para
permitir futuros despliegues en:

- Linux.
- Servidores virtuales.
- Cloud.
- Kubernetes.

## Agentes

La plataforma contempla agentes para:

- Windows.
- Linux.
- Android.
- iOS.

Cada agente informará sus capacidades reales mediante un Capability
Manifest.

El servidor no debe asumir que todas las plataformas pueden ejecutar las
mismas operaciones. Las restricciones de seguridad, permisos y ejecución
en segundo plano deben respetarse individualmente.

## Generación de tráfico

El motor de tráfico será extensible y podrá incluir proveedores como:

- iperf3.
- HTTP upload/download.
- Sockets TCP y UDP nativos.
- Flent.
- Tráfico compuesto.
- Replay controlado de PCAP en nodos especializados.

## Documentación

- `docs/`: documentación técnica y arquitectura general.
- `prompts/`: prompts de desarrollo divididos por fases para Codex.
- `architecture/`: ADRs, diagramas, contratos y modelo de amenazas.
- `scripts/`: scripts de desarrollo, instalación y mantenimiento.
- `AGENTS.md`: reglas permanentes que Codex debe respetar.

## Seguridad y uso autorizado

La plataforma se utilizará exclusivamente sobre dispositivos, servidores,
redes y laboratorios autorizados.

No debe proporcionar una consola remota arbitraria ni permitir la
ejecución de comandos fuera de plugins y acciones expresamente autorizadas.

## Roadmap inicial

1. Arquitectura, ADRs y modelo de amenazas.
2. Monorepo e infraestructura local.
3. Backend, base de datos y autenticación.
4. Contratos y protocolo servidor-agente.
5. Agente de escritorio común.
6. Agente Windows.
7. Agente Linux.
8. Agente Android.
9. Agente iOS.
10. Motor de orquestación.
11. Pruebas básicas de red.
12. Motor extensible de generación de tráfico.
13. Campañas, dashboards y reportes.
14. Seguridad, observabilidad y distribución.
15. Validación end-to-end.
