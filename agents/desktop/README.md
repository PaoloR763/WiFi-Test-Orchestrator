# WTO desktop agent

Shared Python 3.12+ runtime for Windows and Linux agents. Public server communication is
limited to the Phase 04 enrollment, credential rotation, capability manifest and desktop
heartbeat APIs. Task delivery is local/simulated until the authoritative server contract is
published.

The generated `contract_data/` package content is derived from `shared/contracts/`; run
`python scripts/sync_desktop_contracts.py` from the repository root to refresh it and use
`--check` in CI.
