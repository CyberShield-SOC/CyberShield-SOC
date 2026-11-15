"""CyberShield watched-directory log collector (Sprint 7, S7-02.1 / S7-02.4).

The collector watches configured directories, ships new log lines to
``POST /api/ingest`` with source metadata, and remembers what it has already
sent so restarts, log rotation, and copied files do not create duplicates.
It uses only the Python standard library so it can run on monitored hosts
without the backend's dependencies.
"""

__version__ = "0.1.0"
