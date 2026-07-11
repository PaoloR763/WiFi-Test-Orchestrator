# Arquitectura de WiFi Test Orchestrator

## Estado y baseline

Esta carpeta es la ubicación canónica de la arquitectura del producto. La
documentación describe el baseline inicial y todavía no representa una
implementación funcional.

| Elemento | Baseline |
|---|---|
| Producto inicial | `0.1.0` |
| API pública | `v1` |
| JSON Schemas | `1.0.0` |
| Agent Protocol | `1.0.0` |
| Plugin API | `1.0.0` |
| Estado de la fase | Arquitectura documental |

Los números anteriores identifican líneas de compatibilidad independientes.
No implican que existan todavía OpenAPI, JSON Schemas o paquetes ejecutables.

## Autoridad y alcance

El orden de autoridad es:

1. `AGENTS.md` de la raíz, como norma global.
2. ADRs aceptados, que especializan esa norma sin contradecirla.
3. El resto de la documentación arquitectónica.
4. Ejemplos y material explicativo.

Los JSON de `prompts/examples/` son ilustrativos y no normativos. Sus formas,
versiones, nombres y valores no deben utilizarse como contrato. Los contratos
ejecutables se definirán en la Fase 04.

## Objetivos de esta arquitectura

- Asignar cada responsabilidad a un plano y componente identificable.
- Mantener el servidor portable y desacoplado del host Windows.
- Representar capacidades reales y no asumir paridad entre plataformas.
- Separar capabilities funcionales de sus providers o plugins.
- Restringir el tráfico, las capturas y los cambios de infraestructura a
  redes y dispositivos autorizados.
- Permitir evolución compatible de contratos y extensiones.
- Preservar trazabilidad de parámetros, límites, métodos, versiones y tiempo.

## Mapa documental

| Documento | Contenido |
|---|---|
| [System architecture](system-architecture.md) | Contexto, componentes, planos, ownership y dependencias |
| [Deployment topologies](deployment-topologies.md) | Topologías, plataformas y despliegue portable |
| [Runtime flows](runtime-flows.md) | Enrolamiento, entrega, ejecución, reservas y plugins |
| [Quality attributes and assumptions](quality-attributes-and-assumptions.md) | Escala, retención, disponibilidad y supuestos |
| [Contracts and versioning](contracts-and-versioning.md) | Baselines y reglas conceptuales de compatibilidad |
| [Capability matrix](capability-matrix.md) | Modelo multidimensional y panorama por plataforma |
| [Threat model](threat-model.md) | Activos, límites de confianza, amenazas y controles |
| [Glossary](glossary.md) | Términos funcionales y técnicos |
| [Validation](validation.md) | Criterios y estado de validación documental |
| [ADRs](adrs/README.md) | Registro de decisiones arquitectónicas |

Las fuentes Mermaid se encuentran en [diagrams](diagrams/). Cada documento
enlaza los diagramas que utiliza.

## Separación entre contrato y factibilidad

La arquitectura contempla Windows, Linux, Android e iOS desde el inicio. La
primera implementación funcional priorizará servidor, frontend, agente
simulado, Windows y Linux. Que una capability esté contemplada no significa
que esté implementada ni que esté disponible en un dispositivo particular.

Toda afirmación de soporte depende, como mínimo, de la versión del sistema
operativo, hardware, driver, permisos, entitlements y APIs disponibles. Esas
dimensiones se documentan por separado en la matriz de capabilities.

## Convenciones

- La prosa principal se mantiene en español.
- Los nombres de archivos, APIs, capabilities e identificadores técnicos se
  mantienen en inglés.
- Los timestamps persistidos son UTC. La presentación puede usar la zona
  local, sin modificar el valor persistido.
- `reason` es el único nombre conceptual para explicar indisponibilidad o una
  decisión de ejecución; no se define un segundo campo con la misma semántica.
- Un valor de métrica `null` nunca equivale a cero.
- Un límite solicitado `null` significa heredar política; antes de ejecutar
  tráfico debe existir un límite efectivo concreto.

## Decisiones diferidas

Esta fase no congela enumeraciones cerradas, estructuras JSON, OpenAPI, TTL,
algoritmos o formatos criptográficos, representación final de reservas ni
detalles de negociación. Cada asunto se asigna a la fase que debe convertirlo
en un contrato o implementación verificable.

## Criterios de aceptación de la fase

- Los cinco planos y sus responsabilidades están identificados.
- Las tres topologías requeridas están documentadas.
- Las restricciones móviles y de Capture Node son explícitas.
- El modelo de capabilities es multidimensional.
- Los providers pueden incorporarse detrás de interfaces versionadas.
- El threat model cubre abuso de tráfico, captura y credenciales.
- Los ADRs y Mermaid son navegables desde esta carpeta.
