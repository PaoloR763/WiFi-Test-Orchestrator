# Validación documental

## Alcance

La Fase 01 sólo valida documentación, enlaces, ADRs y fuentes Mermaid. No hay
código funcional, schemas, migraciones, infraestructura ni tests de runtime.

## Herramientas

La configuración del repositorio contempla:

- Markdown lint mediante `.markdownlint.json`.
- Link check mediante `lychee.toml`.
- Compilación de cada fuente `.mmd` mediante Mermaid CLI.

Estas herramientas no se descargan ni instalan como parte de esta fase. Una
configuración presente no equivale a una validación ejecutada.

## Validaciones siempre disponibles

- `git diff --check`.
- Revisión manual de enlaces relativos.
- Revisión de secuencia y estructura de ADRs.
- Revisión cruzada entre ADRs, diagramas, capability matrix y threat model.
- Verificación de que `AGENTS.md` y `prompts/` no cambien.
- Revisión de archivos creados, modificados y eliminados.

## Validaciones condicionadas a herramientas existentes

- Markdown lint si `markdownlint` o `markdownlint-cli2` está disponible.
- Link check automatizado si Lychee está disponible.
- Parse/render de Mermaid si Mermaid CLI está disponible.

Si una herramienta no está presente, el handoff debe registrarla como
pendiente. No se sustituye con una afirmación de éxito manual.

## Checklist semántico

- [x] `docs/architecture/` es la única ubicación canónica.
- [x] Todos los ADRs tienen status, context, decision, consequences,
      alternatives, deferred decisions y references.
- [x] API, schemas, Agent Protocol y Plugin API usan los baselines aprobados.
- [x] Las capabilities usan dimensiones separadas.
- [x] Los IDs de capabilities se declaran conceptuales y no normativos.
- [x] iperf3 figura como provider `traffic-provider-iperf3`.
- [x] `reason` es el único campo conceptual de explicación.
- [x] Toda métrica contiene seis elementos conceptuales.
- [x] `null` de métrica no es cero y `null` de límite hereda política.
- [x] Toda prueba de tráfico requiere reserva y límites efectivos.
- [x] FCM/APNs no transportan tareas.
- [x] Todo soporte depende de OS, hardware, driver, permisos, entitlements y APIs.
- [x] RPO/RTO se presentan como provisionales.
- [x] El threat model cubre tráfico, captura, credenciales y plugins.
- [x] No se congelan wire formats, TTL ni formatos criptográficos.

## Estado de ejecución

Estado registrado el 2026-07-11:

| Validación | Resultado real |
|---|---|
| `git diff --check` | Ejecutado correctamente después de corregir una línea final extra en README |
| Enlaces relativos | 106 targets comprobados por existencia y revisión manual; sin faltantes |
| ADRs | 15 archivos secuenciales; headings y `Accepted` comprobados |
| Índice de ADRs | 15 de 15 archivos enlazados |
| Diagramas | 13 de 13 fuentes enlazadas; directivas y bloques revisados estructuralmente |
| Consistencia cruzada | Nueve invariantes críticas verificadas entre ADRs, docs, matriz, threat model y Mermaid |
| Configuración JSON/TOML | Sintaxis comprobada con Python disponible localmente |
| Markdown lint | Pendiente: no hay ejecutable disponible |
| Lychee | Pendiente: no hay ejecutable disponible; `lychee.toml` no fue validado por Lychee |
| Mermaid CLI | Pendiente: no hay ejecutable disponible; no hubo parse ni render automatizado |

No se descargó ni instaló ninguna herramienta para completar estas
validaciones.
