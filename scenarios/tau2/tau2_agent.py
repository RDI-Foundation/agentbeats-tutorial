"""Compatibility wrapper.

The tau2 purple agent now lives in `scenarios/tau2/agent/src/`.
This file is kept so external links and older commands keep working.
"""

import runpy
from pathlib import Path


if __name__ == "__main__":
    runpy.run_path(
        str(Path(__file__).parent / "agent" / "src" / "server.py"),
        run_name="__main__",
    )
