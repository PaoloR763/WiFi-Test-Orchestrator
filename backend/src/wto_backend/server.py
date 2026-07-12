from __future__ import annotations

import uvicorn

from wto_backend.main import app


def main() -> None:
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104 - container ingress is not host-published
        port=8000,
        access_log=False,
        log_config=None,
    )


if __name__ == "__main__":
    main()
