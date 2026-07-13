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
Windows inventory queries each system provider once and applies the finite
`windows_inventory_timeout_seconds` process limit (30 seconds by default).

The generated `contract_data/` package content is derived from `shared/contracts/`; run
`python scripts/sync_desktop_contracts.py` from the repository root to refresh it and use
`--check` in CI.
