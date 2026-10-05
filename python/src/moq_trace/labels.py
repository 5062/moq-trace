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


def objects_per_group(count: int) -> str:
    """Label a group length in objects."""

    return f"{count} {'object' if count == 1 else 'objects'}/group"


def dimension(name: str, value: int) -> str:
    """Label one value of a comparison dimension."""

    if name == "subscribers":
        return subscribers(value)
    if name == "object_size":
        return byte_size(value)
    if name == "objects_per_group":
        return objects_per_group(value)
    raise ValueError(f"unknown comparison dimension: {name}")
