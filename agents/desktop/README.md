# WTO desktop agent

Shared Python 3.12+ runtime for Windows and Linux agents. Public server communication is
limited to the Phase 04 enrollment, credential rotation, capability manifest and desktop
heartbeat APIs. Task delivery is local/simulated until the authoritative server contract is
published.

Phase 06 adds a Windows-only Native Wi-Fi adapter, structured inventory,
locally allowlisted profile administration, a LocalService Windows Service,
service-owned enrollment IPC, diagnostic-only Npcap/dumpcap detection and a
preliminary PyInstaller onedir bundle. It does not implement capture or iperf3.

Windows operations and packaging are documented in `../../docs/phase06/`.
Windows inventory launches seven explicit `powershell.exe` workers with fixed,
locally allowlisted provider commands; it does not use `Start-Job`, PowerShell's
job repository or `StopAsync`. Each worker writes a PID and creation-time marker,
signals ready and waits on a separate start barrier. The coordinator validates
the marker through the stable handle retained from that concrete process,
assigns its tree to a provider-specific Job Object and only then releases it.
PID is diagnostic metadata and is never reopened with termination rights.

The per-provider budgets (drivers/adapters/statistics/IP configuration/
addresses/routes/DNS: 8/8/5/10/5/5/5 seconds) start from the same barrier-release
timestamp. Before release, a guard verifies that the largest budget, the shared
3-second reap and the final 1-second close-and-wait bound fit within the
20-second provider phase. Those bounds plus a 1-second assembly reserve must fit
within the 26-second coordinator planning window; a further 1-second margin is kept
below the external watchdog. If they do not, no provider is released and
inventory fails soft. Startup has a 5-second
bound; a missing marker is terminated without entering its
provider. Stdout/stderr reads are asynchronous, observed and disposed during
cleanup. The external 30-second `windows_inventory_timeout_seconds` remains the
hard safety barrier. Diagnostics are emitted exclusively to stderr; stdout
remains one strict JSON document.

The Windows process runner creates the coordinator with `CREATE_SUSPENDED`,
assigns its original process handle to a kill-on-close Job Object and resumes the
initial thread only after containment. A strong `ProcessContext`, keyed by an
opaque execution token and resolved by process-object identity, owns the Job and
thread handles; `process.pid` is metadata only. The request's absolute deadline
starts before spawn. Cleanup is bounded to 5 seconds and reserves its final
100 ms to force-close the Job, pipes, transport and handles and drain controlled
tasks without replacing the primary exception or cancellation.

The generated `contract_data/` package content is derived from `shared/contracts/`; run
`python scripts/sync_desktop_contracts.py` from the repository root to refresh it and use
`--check` in CI.
