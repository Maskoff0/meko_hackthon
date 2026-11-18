"""
Phase 1 entry point for the fraud detection service.

Delegates to fraud_detection.cli, which runs the end-to-end synthetic
flow: ingest -> trigger -> bounded investigation -> scoped agents ->
Meko write/retrieval -> correlator -> deterministic baseline -> policy
engine -> shadow recommendation -> audit log -> containment gate
(denied in shadow mode).

The old monolithic main.py (which used tools.py directly) is replaced
by the fraud_detection package. main.py remains as a thin shim for
backward compatibility with `python main.py`.

Env: Set MEKO_API_KEY and MEKO_DATAPACK_ID in .env
"""
from __future__ import annotations

import sys

from fraud_detection.cli import main

if __name__ == "__main__":
    sys.exit(main())
