# Uso de los prompts con Codex - WiFi Test Orchestrator v2.0

## 1. Objetivo del paquete

Este paquete divide el desarrollo en fases pequeñas y auditables. Cada prompt debe ejecutarse desde la raíz del repositorio, con `AGENTS.md` presente. No ejecutar todos los prompts en una única sesión: cada fase debe producir código revisable, tests y documentación.

## 2. Preparación

1. Crear el repositorio dentro de WSL2 para obtener mejor rendimiento con Docker Desktop.
2. Copiar `00_AGENTS_master_context.md` como `AGENTS.md` en la raíz.
3. Crear una rama principal protegida y una rama/worktree por fase cuando corresponda.
4. Instalar Git, Docker Desktop/WSL2, Python, Node.js, JDK/Android Studio y Xcode en un Mac para iOS.
5. Guardar secretos solo en `.env` no versionado o secret stores.

## 3. Orden recomendado

Ejecutar los prompts 01 a 26 en orden. No paralelizar antes de completar el Prompt 05 y estabilizar OpenAPI, JSON Schemas, test vectors y contratos de capabilities.

Después del Prompt 05 pueden desarrollarse en paralelo:

- Prompt 06: Windows.
- Prompt 07: Linux/Capture Node.
- Prompt 08: Android.
- Prompt 09: iOS.

Los Prompts 13, 14 y 15 pueden avanzar en paralelo después del Prompt 12, siempre que usen los mismos contratos del `TrafficGenerator`.

## 4. Ciclo de cada fase

```bash
git status
git add .
git commit -m "checkpoint: before phase XX"
```

Prompt previo para Codex:

```text
Antes de implementar, inspeccioná AGENTS.md, docs/architecture, ADRs, migraciones, OpenAPI, JSON Schemas, ejemplos y tests relacionados. Resumí el estado actual, detectá contradicciones y proponé un plan breve. No cambies contratos públicos sin una estrategia de compatibilidad.
```

Después de implementar:

```text
Revisá el diff como reviewer senior. Buscá problemas de seguridad, concurrencia, idempotencia, migraciones, compatibilidad, secretos, lifecycle mobile, permisos, entitlements, supuestos Wi-Fi, generación de tráfico no acotada y tests insuficientes. Corregí los problemas y ejecutá nuevamente lint, type checking, tests, contract tests y migraciones.
```

```bash
git add .
git commit -m "feat: complete phase XX"
```

## 5. Evidencia obligatoria

Cada fase debe dejar en su handoff:

- Archivos creados/modificados.
- Decisiones y ADRs.
- Comandos ejecutados y resultado.
- Tests agregados.
- Métricas de cobertura relevantes.
- Riesgos, limitaciones y deuda técnica.
- Instrucciones de rollback.
- Impacto en contratos, migraciones y compatibilidad.

## 6. Reglas de trabajo paralelo

- Usar worktrees para agentes por plataforma.
- No editar simultáneamente el mismo schema desde dos ramas.
- Integrar primero contratos y test vectors, luego implementaciones.
- Rebasear y ejecutar toda la matriz de contract tests antes de mergear.
- En iOS se requiere un host macOS con Xcode; Codex en Windows no puede compilar ni firmar una app iOS localmente.

## 7. Archivos de ejemplo

La carpeta `examples/` contiene mensajes y manifests de referencia. Deben convertirse en golden fixtures usados por los contract tests de Python, TypeScript, Kotlin y Swift.
