# ADR-0001: Technology stack and portable OCI deployment

## Status

Accepted

## Context

El entorno inicial de desarrollo es Windows 11 con Docker Desktop y WSL2, y el
repositorio permanece por ahora en `C:\Dev`. Esa conveniencia local no puede
convertirse en una dependencia del dominio, de los contratos ni de la operación
del servidor. Los servicios deben poder ejecutarse en Linux, macOS y entornos
cloud sin alterar su comportamiento observable.

La primera versión del producto es `0.1.0`. Como supuestos iniciales de diseño se
consideran hasta 500 agentes registrados, 100 agentes online simultáneamente,
25 pruebas de tráfico concurrentes y 10 campañas concurrentes. Durante una
prueba se espera telemetría cada 5 segundos y, fuera de pruebas, cada 30 a 60
segundos. La retención objetivo es de 30 días para datos detallados y 12 meses
para datos agregados.

El MVP no tendrá alta disponibilidad. Los objetivos provisionales son RPO de
24 horas y RTO de 4 horas; son hipótesis de arquitectura y no un SLA demostrado.

## Decision

Los servicios de servidor se empaquetarán como contenedores Linux compatibles
con OCI. No usarán rutas absolutas del checkout, Windows Services, Registry,
named pipes ni APIs exclusivas del host Windows. El path `C:\Dev` sólo describe
la ubicación actual del repositorio y no aparecerá en imágenes, contratos ni
configuración portable.

El stack base es:

- Backend con Python 3.12 o superior, FastAPI, SQLAlchemy 2, Alembic y Pydantic 2.
- Frontend con React, TypeScript y Vite.
- PostgreSQL como fuente de verdad transaccional.
- Redis para coordinación, locks, rate limits y cola.
- Celery, u otro worker compatible, detrás de una interfaz de ejecución que
  evite acoplar el dominio a un framework concreto.
- Artefactos detrás de una abstracción compatible con filesystem local y
  S3/MinIO.
- Agentes Windows y Linux en Python, con SQLite local y adaptadores por sistema
  operativo.
- Android nativo en Kotlin con Jetpack, Room, WorkManager, Retrofit/OkHttp y APIs
  de red soportadas.
- iOS/iPadOS nativo en Swift/SwiftUI con URLSession, Network.framework,
  BackgroundTasks y Keychain.

Las plataformas mínimas contempladas por la arquitectura son Windows 10 22H2 y
Windows 11, Ubuntu 22.04 o superior como referencia Linux, Android 10/API 29 o
superior e iOS 16 o superior. Contemplar una plataforma en los contratos no
implica que su agente ya esté implementado.

La primera implementación funcional priorizará servidor, frontend, agente
simulado y agentes Windows y Linux. Android e iOS permanecerán dentro del modelo
arquitectónico y contractual desde el inicio, con su implementación diferida y
sin presentar capacidades inexistentes como disponibles.

El MVP tendrá un único control plane lógico y no prometerá failover automático.
Las topologías con traffic nodes, Capture Nodes o componentes distribuidos
separan roles y carga, pero no convierten al MVP en una solución de alta
disponibilidad.

La arquitectura no presupone que linters, renderers, runtimes, CLIs u otras
herramientas estén instalados en una estación concreta. Su disponibilidad debe
comprobarse antes de usarlos y documentarse como evidencia de cada validación.

## Consequences

- El mismo dominio y los mismos contratos pueden desplegarse sobre hosts
  diferentes sin ramas específicas para Windows.
- El desarrollo local requiere mapear volúmenes, networking y secrets mediante
  mecanismos portables en vez de depender del filesystem del host.
- PostgreSQL, Redis y el artifact store tienen responsabilidades distintas y
  deben observarse, respaldarse y restaurarse de forma coherente.
- La ausencia de alta disponibilidad deja puntos únicos de falla en el MVP.
- Los objetivos de escala, retención, RPO y RTO necesitan validación mediante
  pruebas de capacidad y ejercicios de backup/restore antes de considerarse
  compromisos operativos.
- Mantener cuatro plataformas en el diseño contractual aumenta el costo de
  compatibilidad aunque las implementaciones móviles lleguen después.

## Alternatives considered

- **Servicios de servidor nativos de Windows:** descartados porque crearían
  dependencias funcionales del host y dificultarían la portabilidad.
- **Kubernetes obligatorio desde el primer release:** descartado para el MVP por
  complejidad operativa y porque no resuelve por sí mismo persistencia ni alta
  disponibilidad.
- **Un proceso único con almacenamiento local embebido:** descartado porque
  mezcla responsabilidades y limita coordinación, trazabilidad y crecimiento.
- **Excluir Android e iOS hasta su implementación:** descartado porque produciría
  contratos centrados en desktop y cambios incompatibles posteriores.

## Deferred decisions

- Definiciones OCI concretas, imágenes base, pinning de dependencias y archivos
  de orquestación local.
- Topología cloud/Kubernetes, alta disponibilidad y disaster recovery más allá
  del MVP.
- Dimensionamiento medido, estrategia de particionado y resolución de datos
  agregados.
- Política, alcance y frecuencia de backups; validación o ajuste de RPO y RTO.
- Herramientas y versiones concretas para lint, links check y validación de
  documentación.

## References

- [AGENTS.md, secciones 2, 3, 10 y 12](../../../AGENTS.md)
- [ADR-0002: Domain and plane boundaries](0002-domain-and-plane-boundaries.md)
- [ADR-0005: Outbound task delivery, leases and idempotency](0005-outbound-task-delivery-leases-and-idempotency.md)
