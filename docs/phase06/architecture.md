# Arquitectura Windows

`WindowsPlatformAdapter` compone collectors, control local, ProcessRunner, Credential Manager,
ServiceManager y detección de captura. El core no importa pywin32 ni `ctypes.WinDLL`.

```mermaid
flowchart LR
  A[CLI o Windows Service] --> B[Application]
  B --> C[WindowsPlatformAdapter]
  C --> D[Native Wi-Fi]
  C --> E[IP Helper]
  C --> F[PowerShell JSON]
  C --> G[netsh fallback]
  C --> H[SCM y Credential Manager]
```

La fusión se realiza por campo en orden Native Wi-Fi, API estructurada, PowerShell y netsh. Una
fuente parcial no invalida el snapshot. `collected_at` existe sólo en el modelo interno; no se
agrega al contrato público Metric 1.0.0.
