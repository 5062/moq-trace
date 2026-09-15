"""Shared failures for trace analysis and artifact handling."""


class TraceError(RuntimeError):
    """A trace could not be captured, analyzed, or rendered reliably."""
