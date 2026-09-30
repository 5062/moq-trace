"""Human-readable labels for workload quantities, shared by the runner and the figures."""


def byte_size(value: int) -> str:
    """Label a byte count using an exact binary unit when possible."""

    for divisor, suffix in ((1024 * 1024, "MiB"), (1024, "KiB")):
        if value % divisor == 0:
            return f"{value // divisor} {suffix}"
    return f"{value} bytes"


def subscribers(count: int) -> str:
    """Label a subscriber count."""

    return f"{count} {'subscriber' if count == 1 else 'subscribers'}"
