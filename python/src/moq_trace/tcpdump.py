"""A full packet capture of the relay's UDP port."""

from __future__ import annotations

import os
import pathlib

from .errors import CaptureError
from .hosts import Host, Process

# Environment variable holding the sudo password for the packet capture, for
# hosts where sudo asks for one.
SUDO_PASSWORD_ENVIRONMENT = "MOQ_TRACE_SUDO_PASSWORD"
_sudo_password: str | None = None


def take_sudo_password() -> str | None:
    """Move the sudo password out of the environment and keep it in memory.

    Taken before the first child process starts, it is inherited by none of
    them: not the relay, the peers, or an LTTng session daemon that outlives
    the run. It then reaches only sudo, through standard input.
    """

    global _sudo_password
    if SUDO_PASSWORD_ENVIRONMENT in os.environ:
        _sudo_password = os.environ.pop(SUDO_PASSWORD_ENVIRONMENT)
    return _sudo_password


def packet_capture_command(pcap: str, port: int, user: str, password: bool = False) -> list[str]:
    """Capture every UDP datagram on `port` whole, on every interface.

    Capturing needs privileges, so tcpdump runs under sudo and drops them to
    `user` before writing, which keeps the file readable by the analysis. With
    `password`, sudo reads the password from standard input without prompting;
    otherwise it must not need one. `LINUX_SLL2` records the interface and
    direction of each packet, which the analysis needs to count a loopback
    datagram once. The payloads are captured whole, because analysis decrypts
    them with the peers' key logs, and a 64 MiB kernel buffer keeps a capture
    of whole payloads from dropping datagrams, which analysis rejects.
    """

    sudo = ["sudo", "-S", "-p", ""] if password else ["sudo", "-n"]
    return [
        *sudo,
        "tcpdump",
        "-i",
        "any",
        "-y",
        "LINUX_SLL2",
        "-s",
        "0",
        "-B",
        "65536",
        "--time-stamp-precision",
        "nano",
        "-U",
        "-Z",
        user,
        "-w",
        pcap,
        "udp",
        "port",
        str(port),
    ]


async def start_packet_capture(host: Host, directory: str, port: int, log: pathlib.Path) -> Process:
    """Start a packet capture into `directory/relay.pcap` on `host` and wait until tcpdump listens.

    tcpdump opens its file after dropping from root to the login user, and that
    process may lack the credentials a network home directory requires, as with
    Kerberos NFS, so `directory` should be on local disk.
    """

    password = take_sudo_password()
    command = packet_capture_command(f"{directory}/relay.pcap", port, host.user, password is not None)
    stdin = None if password is None else f"{password}\n".encode()
    process = await host.start("tcpdump", command, directory, log, stdin=stdin)
    try:
        await process.wait_for_line(lambda line: "listening on" in line, "tcpdump listening", 10)
    except CaptureError as error:
        await process.close()
        reason = process.lines[-1] if process.lines else str(error)
        sudo = "password" in reason or "sudo" in reason
        hint = f"tcpdump needs sudo: set {SUDO_PASSWORD_ENVIRONMENT} or allow it without a password; " if sudo else ""
        raise CaptureError(f"packet capture failed: {reason} ({hint}see {log})") from error
    return process
