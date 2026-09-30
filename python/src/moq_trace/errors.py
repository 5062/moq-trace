"""Shared failures for capture, trace analysis, and artifact handling."""


class TraceError(RuntimeError):
    """A trace could not be captured, analyzed, or rendered reliably."""


class CaptureError(RuntimeError):
    """A host, process, or LTTng operation of a capture failed."""
