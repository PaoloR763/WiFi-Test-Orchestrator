# Recuperación, idempotencia y rollback

## Garantías exactas

- La recepción y deduplicación local se confirma exactamente una vez por
  `task_id` y efecto lógico.
- Existe un único claim durable por `idempotency_key`.
- Después del claim, el plugin se invoca como máximo una vez.
- Un crash posterior al claim nunca vuelve a poner la task en `queued`.
- Progress, results y uploads usan outbox at-least-once con IDs estables.
- Efectos externos sólo pueden ser exactly-once si el plugin futuro implementa
  reconciliación, checkpoint o idempotencia propia.

Existe una ventana inevitable entre persistir `claimed_at`/`invoked_at` e
invocar código Python. Un crash allí puede dejar una task `interrupted` sin que
el efecto haya comenzado. Se elige no redispatch para evitar duplicar un efecto
que podría haber comenzado.

## Reinicio

Tasks `preparing`, `running`, `cancel_requested` o `cleaning_up` pasan a
`interrupted`, conservan el intento único y dejan cleanup solicitado. Tasks
todavía `queued` sí pueden ejecutarse. Resultados ya persistidos permanecen en
outbox hasta ack.

## Rotación

La idempotency key de create se persiste antes de pedir la pending credential.
Active y pending viven simultáneamente en SecretStore durante el cutover. La
activation key también se persiste antes de activar. Si el ack se pierde, se
repite activation con la pending y la misma key. Tras confirmación, SQLite
apunta a la nueva credential, se elimina la anterior y luego se limpian los
metadatos transitorios. Un crash entre esos pasos reanuda la limpieza.

## Rollback

Fase 05 introduce sólo schema SQLite local. Para rollback, detener el agente,
preservar la base y restaurar el backup verificado anterior a la migración. No
hay downgrade DDL automático. Volver a un binario que no comprenda `user_version`
debe fallar cerrado; nunca borrar la base para ocultar incompatibilidad.
