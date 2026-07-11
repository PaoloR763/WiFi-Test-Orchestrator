# Prompt 19 - Artefactos, captura IP y reportes

## Objetivo

Implementar almacenamiento seguro de artefactos, captura permitida por plataforma y reportes trazables.

## Prerrequisitos

- Prompts 06-18 completos.

## Alcance

- Artifact store.
- Multipart upload.
- Hashes.
- Capture providers.
- Report renderers.
- Retention.

## Requisitos de implementación

- Artifact manifest con type, media_type, size, sha256, source, execution y retention class.
- Upload resumable y cuotas.
- Filesystem local y backend S3/MinIO.
- Windows: Npcap/dumpcap opcional; Linux: dumpcap/tcpdump; Android VpnService solo fase opcional con consentimiento; iOS sin captura general por defecto.
- CaptureProvider con filtros, interface mapping, duration y max size.
- PCAP analysis básico con tshark en worker aislado.
- Reportes HTML/PDF/CSV/JSON con snapshot, plataforma, methods, availability, thresholds y motivos.
- Redacción de secretos/PII.
- Signed URLs o autorización por descarga.
- Expiración y legal hold opcional.
- No incrustar PCAP completo en PDF.

## Tests obligatorios

- Upload interrumpido.
- Hash mismatch.
- Quota.
- Unauthorized download.
- Capture timeout.
- Report deterministic.
- Retention deletion.
- Malicious filename.

## Documentación obligatoria

- Catálogo de artefactos.
- Política de retención.
- Guía de captura.
- Template de reporte y limitaciones.

## Criterios de aceptación

- Artefactos íntegros.
- Captura acotada.
- Reportes reproducibles.
- Acceso auditado.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
