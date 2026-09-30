"""The failures this tool reports as expected errors rather than as bugs."""


class MoqTraceError(RuntimeError):
    """Base of every expected failure, which the command line reports without a traceback."""


class CaptureError(MoqTraceError):
    """A host, process, or LTTng operation of a capture failed."""


class ExperimentError(MoqTraceError):
    """An experiment's configuration or workload was not met."""


class TraceError(MoqTraceError):
    """A trace could not be analyzed, or an artifact read or rendered reliably."""


class CtfError(TraceError):
    """The CTF input is incomplete or incompatible with the analyzer schema."""
