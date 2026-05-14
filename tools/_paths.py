"""Shared binary-path configuration.

Set these via environment variables before running any tool::

    set "CHERAX_LOADER=C:\\path\\to\\CheraxLoader.exe"
    set "CHERAX_MODULE=C:\\path\\to\\3790447328.dll"

Or pass ``--loader`` / ``--module`` flags where supported.
"""
import os, sys

LOADER_PATH = os.environ.get("CHERAX_LOADER", "")
DLL_PATH    = os.environ.get("CHERAX_MODULE", "")

def require(name: str, path: str) -> str:
    if not path:
        sys.stderr.write(
            f"ERROR: {name} not configured.\n"
            f"  set CHERAX_LOADER=...   for loader EXE\n"
            f"  set CHERAX_MODULE=...   for decrypted module DLL\n"
        )
        sys.exit(2)
    if not os.path.isfile(path):
        sys.stderr.write(f"ERROR: {name} = {path!r} — file not found\n")
        sys.exit(2)
    return path
