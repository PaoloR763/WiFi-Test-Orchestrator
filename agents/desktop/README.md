# WTO desktop agent

Shared Python 3.12+ runtime for Windows and Linux agents. Public server communication is
limited to the Phase 04 enrollment, credential rotation, capability manifest and desktop
heartbeat APIs. Task delivery is local/simulated until the authoritative server contract is
published.

Phase 06 adds a Windows-only Native Wi-Fi adapter, structured inventory,
locally allowlisted profile administration, a LocalService Windows Service,
service-owned enrollment IPC, diagnostic-only Npcap/dumpcap detection and a
preliminary PyInstaller onedir bundle. It does not implement capture or iperf3.

Phase 07 replaces the Linux stub with a NetworkManager D-Bus-first adapter,
structured ip/iw/ethtool fallbacks, explicit encrypted headless secret storage, hardened
systemd endpoint/Capture Node services and a private, offline DEB runtime with
Pydantic 2. Capture uses an explicit specialized role, frequency/channel/size/
duration policy, idempotent artifact preflight, a fully restorable snapshot,
durable pre-change journal and verified rollback. Confirmed artifact retention
is explicit and bounded. Capture retries use a versioned functional fingerprint,
immutable binding and a durable recovery marker created before PCAP reservation;
state and artifact roots may be separate filesystems. Linux doctor is a
read-only composition and empty `iw link` output remains unavailable rather
than disconnected. Tcpreplay is validation/simulation only and no
optional tool is installed by the agent package. See
`../../docs/phase07/`.

Linux keeps the Phase 05 fail-closed default: omitting `linux_secret_backend`
selects `secret_service`; `auto` is retained as a compatibility spelling with
the same behavior and never falls back to persistent files. Headless files
require explicit `linux_secret_backend = "encrypted_file"` (the DEB examples do
so). Secret Service uses a 5-second total budget and a 2-second per-call bound,
configurable with the validated `linux_secret_service_*_timeout_seconds`
settings. NetworkManager inventory has one total monotonic budget and capability
publication reports only providers that pass their current productive probe.

Windows operations and packaging are documented in `../../docs/phase06/`.
Windows inventory launches seven explicit `powershell.exe` workers with fixed,
locally allowlisted provider commands; it does not use `Start-Job`, PowerShell's
job repository or `StopAsync`. Each worker writes a PID and creation-time marker,
signals ready and waits on a separate start barrier. The coordinator validates
the marker through the stable handle retained from that concrete process,
assigns its tree to a provider-specific Job Object and only then releases it.
Ready observation and marker parsing/validation are independent conditions; if
ready is observed first, the coordinator keeps waiting for the marker through
the 5-second startup deadline without opening the barrier.
PID is diagnostic metadata and is never reopened with termination rights.

The per-provider budgets (drivers/adapters/statistics/IP configuration/
addresses/routes/DNS: 8/8/5/10/5/5/5 seconds) start from the same barrier-release
timestamp. Before release, a guard verifies that the largest budget, the shared
3-second reap and the final 1-second close-and-wait bound fit within the
20-second provider phase. Those bounds plus a 1-second assembly reserve must fit
within the 26-second coordinator planning window; a further 1-second margin is kept
below the external watchdog. If they do not, no provider is released and
inventory fails soft. Startup has a 5-second
bound independent of the provider budgets; a missing marker is terminated by
the retained stable handle without entering its provider. Stdout/stderr reads
are asynchronous, observed and disposed during
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
