# Prompt 01 - Arquitectura, ADRs y modelo de amenazas

## Objetivo

Definir la arquitectura objetivo antes de escribir funcionalidades, incluyendo límites de dominio, deployment, seguridad, capabilities, extensibilidad y restricciones por plataforma.

## Prerrequisitos

- Repositorio inicial con AGENTS.md.
- No se requiere código funcional todavía.

## Alcance

- Diagramas de contexto, contenedores y componentes.
- ADRs para stack, contratos, cola, almacenamiento, mobile lifecycle, tráfico, captura y plugins.
- Threat model con activos, actores, fronteras de confianza y controles.
- Matriz de capacidades Windows/Linux/Android/iOS/Capture Node.
- Glosario técnico y lista de supuestos.

## Requisitos de implementación

- Crear `docs/architecture/` con diagramas Mermaid versionados.
- Separar control plane, data plane, telemetry plane, artifact plane e integration plane.
- Definir topologías de laboratorio: servidor único, servidor + traffic nodes y deployment distribuido.
- Definir disponibilidad, escalabilidad inicial y límites del MVP.
- Definir modelo de capability con versión, condición, permisos, límites y reason.
- Definir estrategia de compatibilidad de contratos y plugin API.
- Registrar cada decisión relevante como ADR con status, contexto, decisión, consecuencias y alternativas.

## Tests obligatorios

- Validar sintaxis Mermaid.
- Añadir lint/links check para documentación.
- Revisión de threat model contra casos de abuso de generación de tráfico, captura y credenciales.

## Documentación obligatoria

- README de arquitectura.
- ADRs numerados.
- Matriz de capacidades y limitaciones.
- Diagrama de secuencia de enrolamiento y ejecución.

## Criterios de aceptación

- La arquitectura puede explicar dónde vive cada responsabilidad.
- No existen dependencias funcionales del servidor respecto del host Windows.
- Las restricciones mobile están explícitas.
- Los futuros plugins pueden añadirse sin modificar el núcleo.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
