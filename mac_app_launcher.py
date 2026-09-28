"""Launch the bundled Streamlit application on the local Mac only."""

from __future__ import annotations

import socket
import sys
from pathlib import Path


def local_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def main() -> None:
    from streamlit.web import cli as streamlit_cli

    bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    application = bundle_dir / "mac_to_autopsy_triage.py"
    if not application.is_file():
        raise RuntimeError(f"Bundled application source is missing: {application}")
    sys.argv = [
        "streamlit", "run", str(application),
        "--global.developmentMode=false",
        "--server.address=127.0.0.1",
        f"--server.port={local_port()}",
        "--server.headless=false",
        "--browser.gatherUsageStats=false",
        "--server.enableXsrfProtection=true",
        "--server.enableCORS=true",
    ]
    streamlit_cli.main()


if __name__ == "__main__":
    main()
