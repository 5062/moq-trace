"""Decrypt the QUIC version 1 packets of a packet capture with TLS key logs.

The relay's capture holds every datagram on its port, and the bench peers'
key logs hold the secrets of every connection that ends at them. Together they
show what went over the wire, independently of the relay's own trace: each
packet's capture time, number, and STREAM frames.

Decryption follows RFC 9001. Initial keys derive from the client's first
Destination Connection ID. Handshake and 1-RTT keys derive from the key log
secrets of the connection's ClientHello random, which the client's Initial
packets carry. A key update derives the next 1-RTT keys with `quic ku`.

A capture taken before the kernel segments a GSO send holds the whole send as
one datagram, and the segment size is not in the capture. A short-header packet
extends to the end of its datagram, so a segment boundary is found by trial: a
later segment starts with a packet of the same connection, which repeats the
first packet's Destination Connection ID, and only a boundary at which the
first packet authenticates is accepted. An AEAD tag verifies by chance with
probability 2^-128, so a wrong boundary cannot pass.

Every defect is an error rather than a skipped packet: the capture is the
reference the trace is checked against, so it must not lose packets silently.
"""

from __future__ import annotations

import dataclasses
import hmac
from collections.abc import Iterable, Iterator, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from ..errors import TraceError

VERSION_1 = 0x0000_0001
# RFC 9001 section 5.2.
INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

# Packet number spaces, named as the trace names them.
INITIAL = "initial"
HANDSHAKE = "handshake"
ZERO_RTT = "zero_rtt"
DATA = "data"

CLIENT = "client"
SERVER = "server"

_LONG_TYPES = {0: INITIAL, 1: ZERO_RTT, 2: HANDSHAKE, 3: "retry"}


@dataclasses.dataclass(frozen=True)
class Suite:
    """A TLS 1.3 cipher suite as QUIC packet protection uses it."""

    name: str
    key_length: int
    hash: hashes.HashAlgorithm
    chacha: bool


SUITES = {
    0x1301: Suite("TLS_AES_128_GCM_SHA256", 16, hashes.SHA256(), False),
    0x1302: Suite("TLS_AES_256_GCM_SHA384", 32, hashes.SHA384(), False),
    0x1303: Suite("TLS_CHACHA20_POLY1305_SHA256", 32, hashes.SHA256(), True),
}
_INITIAL_SUITE = SUITES[0x1301]


def hkdf_extract(salt: bytes, secret: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    """HKDF-Extract (RFC 5869) with `algorithm`."""

    return hmac.new(salt, secret, algorithm.name).digest()


def expand_label(secret: bytes, label: str, length: int, algorithm: hashes.HashAlgorithm) -> bytes:
    """TLS 1.3 HKDF-Expand-Label with an empty context (RFC 8446 section 7.1)."""

    full = b"tls13 " + label.encode()
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(algorithm, length, info).derive(secret)


class Keys:
    """The packet protection keys of one sender for one key generation."""

    def __init__(self, suite: Suite, secret: bytes, hp: bytes | None = None) -> None:
        self.suite = suite
        self.secret = secret
        self.key = expand_label(secret, "quic key", suite.key_length, suite.hash)
        self.iv = expand_label(secret, "quic iv", 12, suite.hash)
        # A key update replaces the packet keys but keeps the header protection
        # key (RFC 9001 section 6).
        self.hp = expand_label(secret, "quic hp", suite.key_length, suite.hash) if hp is None else hp
        self._aead = ChaCha20Poly1305(self.key) if suite.chacha else AESGCM(self.key)
        self._hp_cipher = None if suite.chacha else Cipher(algorithms.AES(self.hp), modes.ECB())

    def mask(self, sample: bytes) -> bytes:
        """Return the five header protection mask bytes for a 16-byte sample."""

        if self.suite.chacha:
            # The sample's first four bytes are the block counter and the rest the
            # nonce, which is the 16-byte nonce `cryptography` takes.
            encryptor = Cipher(algorithms.ChaCha20(self.hp, sample), mode=None).encryptor()
            return encryptor.update(b"\x00" * 5)
        return self._hp_cipher.encryptor().update(sample)[:5]

    def nonce(self, packet_number: int) -> bytes:
        """Return the AEAD nonce of a packet number."""

        return bytes(a ^ b for a, b in zip(self.iv, packet_number.to_bytes(12, "big"), strict=True))

    def open(self, packet_number: int, header: bytes, ciphertext: bytes) -> bytes:
        """Decrypt and authenticate a payload, raising `InvalidTag` on failure."""

        return self._aead.decrypt(self.nonce(packet_number), ciphertext, header)

    def seal(self, packet_number: int, header: bytes, plaintext: bytes) -> bytes:
        """Encrypt a payload, as the sender did."""

        return self._aead.encrypt(self.nonce(packet_number), plaintext, header)

    def updated(self) -> Keys:
        """Return the keys of the next key generation."""

        secret = expand_label(self.secret, "quic ku", self.suite.hash.digest_size, self.suite.hash)
        return Keys(self.suite, secret, self.hp)


def initial_keys(destination_connection_id: bytes) -> dict[str, Keys]:
    """Return the version 1 Initial keys of each sender for a client's first DCID."""

    algorithm = _INITIAL_SUITE.hash
    secret = hkdf_extract(INITIAL_SALT, destination_connection_id, algorithm)
    return {
        CLIENT: Keys(_INITIAL_SUITE, expand_label(secret, "client in", 32, algorithm)),
        SERVER: Keys(_INITIAL_SUITE, expand_label(secret, "server in", 32, algorithm)),
    }


def decode_packet_number(truncated: int, length: int, largest: int | None) -> int:
    """Expand a truncated packet number (RFC 9000 appendix A.3)."""

    expected = 0 if largest is None else largest + 1
    window = 1 << (8 * length)
    half = window // 2
    candidate = (expected & ~(window - 1)) | truncated
    if candidate <= expected - half and candidate < (1 << 62) - window:
        return candidate + window
    if candidate > expected + half and candidate >= window:
        return candidate - window
    return candidate


class _Reader:
    """Read QUIC variable-length integers and byte runs from a buffer."""

    def __init__(self, data: bytes, position: int = 0, end: int | None = None) -> None:
        self.data = data
        self.position = position
        self.end = len(data) if end is None else end

    def remaining(self) -> int:
        return self.end - self.position

    def byte(self) -> int:
        if self.position >= self.end:
            raise _Malformed("truncated")
        value = self.data[self.position]
        self.position += 1
        return value

    def bytes(self, length: int) -> bytes:
        if length < 0 or self.position + length > self.end:
            raise _Malformed("truncated")
        value = self.data[self.position : self.position + length]
        self.position += length
        return value

    def varint(self) -> int:
        first = self.byte()
        length = 1 << (first >> 6)
        value = first & 0x3F
        for _ in range(length - 1):
            value = (value << 8) | self.byte()
        return value


class _Malformed(Exception):
    """A packet or frame that does not parse."""


class _Undecryptable(Exception):
    """A packet that does not authenticate under the keys and boundary tried."""


# Key log labels (NSS key log format) and the packet space and sender each keys.
_SECRETS = {
    "CLIENT_EARLY_TRAFFIC_SECRET": (ZERO_RTT, CLIENT),
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET": (HANDSHAKE, CLIENT),
    "SERVER_HANDSHAKE_TRAFFIC_SECRET": (HANDSHAKE, SERVER),
    "CLIENT_TRAFFIC_SECRET_0": (DATA, CLIENT),
    "SERVER_TRAFFIC_SECRET_0": (DATA, SERVER),
}


def read_key_log(lines: Iterable[str], source: str = "key log") -> dict[bytes, dict[str, bytes]]:
    """Parse NSS key log lines into secrets keyed by ClientHello random and label.

    Labels this analysis does not use, such as TLS 1.2 secrets or exporter
    secrets, are ignored. Two different secrets for one random and label are an
    error, because they cannot both describe the connection.
    """

    secrets: dict[bytes, dict[str, bytes]] = {}
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3:
            raise TraceError(f"{source} line {number} is not `LABEL CLIENT_RANDOM SECRET`")
        label, random_hex, secret_hex = fields
        if label not in _SECRETS:
            continue
        try:
            random, secret = bytes.fromhex(random_hex), bytes.fromhex(secret_hex)
        except ValueError as error:
            raise TraceError(f"{source} line {number} holds a value that is not hexadecimal") from error
        known = secrets.setdefault(random, {})
        if known.get(label, secret) != secret:
            raise TraceError(f"{source} holds two different {label} secrets for one ClientHello random")
        known[label] = secret
    return secrets


def merge_key_logs(logs: Iterable[Mapping[bytes, Mapping[str, bytes]]]) -> dict[bytes, dict[str, bytes]]:
    """Merge parsed key logs, rejecting conflicting secrets."""

    merged: dict[bytes, dict[str, bytes]] = {}
    for log in logs:
        for random, labels in log.items():
            known = merged.setdefault(random, {})
            for label, secret in labels.items():
                if known.get(label, secret) != secret:
                    raise TraceError(f"the key logs hold two different {label} secrets for one ClientHello random")
                known[label] = secret
    return merged


@dataclasses.dataclass(frozen=True)
class StreamFrame:
    """A STREAM frame's half-open byte range."""

    stream_id: int
    offset_start: int
    offset_end: int
    fin: bool


@dataclasses.dataclass(frozen=True)
class Packet:
    """One decrypted QUIC packet as the capture saw it.

    `sender` is `client` or `server`. `datagram` numbers the captured datagram,
    `segment` the GSO segment within it, and `index` the packet within the
    datagram, so coalesced packets keep their order.
    """

    timestamp_ns: int
    connection: int
    sender: str
    space: str
    packet_number: int
    byte_length: int
    datagram: int
    segment: int
    index: int
    stream_frames: tuple[StreamFrame, ...]


@dataclasses.dataclass
class Connection:
    """The decryption state of one QUIC connection on one address pair."""

    index: int
    # The addresses as `(ip, port)`; `local` is the capture side's, the relay's.
    local: tuple[str, int]
    peer: tuple[str, int]
    # Which endpoint sent the first client Initial: the peer or the local side.
    client_is_peer: bool
    client_scid: bytes
    initial: dict[str, Keys]
    first_ns: int
    last_ns: int
    suite: Suite | None = None
    client_random: bytes | None = None
    handshake: dict[str, Keys] = dataclasses.field(default_factory=dict)
    zero_rtt: Keys | None = None
    # 1-RTT key generations of each sender; the current one is `generation`.
    generations: dict[str, list[Keys]] = dataclasses.field(default_factory=dict)
    generation: dict[str, int] = dataclasses.field(default_factory=dict)
    # The connection ID length of each endpoint, which is the DCID length of
    # short-header packets sent to it.
    cid_length: dict[str, int] = dataclasses.field(default_factory=dict)
    # IDs issued by each endpoint, including replacements advertised in frames.
    cids: dict[str, set[bytes]] = dataclasses.field(default_factory=dict)
    largest: dict[tuple[str, str], int] = dataclasses.field(default_factory=dict)
    # CRYPTO bytes from offset 0 of each sender's Initial space, kept only until
    # the ClientHello random and ServerHello cipher suite are read.
    crypto: dict[str, dict[int, bytes]] = dataclasses.field(default_factory=dict)

    def sender(self, from_peer: bool) -> str:
        """Name the endpoint that sent a datagram, given whether the peer sent it."""

        return CLIENT if from_peer == self.client_is_peer else SERVER


@dataclasses.dataclass(frozen=True)
class _Decrypted:
    space: str
    packet_number: int
    end: int
    payload: bytes
    sender: str
    connection: Connection
    # Set when the packet is the first of a new connection.
    new_connection: bool
    # The 1-RTT generation the packet used, which becomes current on commit.
    generation: int | None
    # Connection IDs learned from the long header, applied on commit.
    cids: tuple[tuple[str, bytes], ...]


class Decryptor:
    """Decrypt the datagrams of one relay port in capture order."""

    def __init__(self, secrets: Mapping[bytes, Mapping[str, bytes]]) -> None:
        self.secrets = secrets
        self.connections: list[Connection] = []
        # Several connections can share a UDP socket and therefore an address pair.
        self._current: dict[tuple[tuple[str, int], tuple[str, int]], list[Connection]] = {}
        self._datagrams = 0

    def datagram(
        self,
        timestamp_ns: int,
        local: tuple[str, int],
        peer: tuple[str, int],
        from_peer: bool,
        payload: bytes,
    ) -> list[Packet]:
        """Decrypt every packet of one captured datagram, splitting GSO segments."""

        datagram = self._datagrams
        self._datagrams += 1
        packets: list[Packet] = []
        position = 0
        segment_size: int | None = None
        segment_start = 0
        segment = 0
        length = len(payload)
        while position < length:
            if segment_size is not None:
                while position >= segment_start + segment_size:
                    segment_start += segment_size
                    segment += 1
            first = payload[position]
            end = length if segment_size is None else min(segment_start + segment_size, length)
            if position > segment_start and not any(payload[position:end]):
                # Zero padding after a segment's last packet. A packet cannot be
                # recognized by its fixed bit, because a peer that negotiated
                # RFC 9287 greases it, but its protected bytes are never all zero.
                position = end
                continue
            if first & 0x80:
                version = int.from_bytes(payload[position + 1 : position + 5], "big")
                if version == 0:
                    # Version negotiation carries no packet number and fills its datagram.
                    position = length if segment_size is None else min(segment_start + segment_size, length)
                    continue
                if version != VERSION_1:
                    raise TraceError(f"datagram {datagram} from {peer} uses QUIC version {version:#x}, not version 1")
                if _LONG_TYPES[(first & 0x30) >> 4] == "retry":
                    self._retry(local, peer, payload[position:], from_peer, timestamp_ns)
                    position = length if segment_size is None else min(segment_start + segment_size, length)
                    continue
                decrypted = self._long(timestamp_ns, local, peer, from_peer, payload, position)
            else:
                connection = self._connection(local, peer, datagram, from_peer, payload, position)
                if segment_size is None:
                    decrypted = self._first_short(connection, from_peer, payload, position, datagram)
                    if decrypted.end < length:
                        segment_size = decrypted.end - segment_start
                else:
                    end = min(segment_start + segment_size, length)
                    try:
                        decrypted = self._short(connection, from_peer, payload, position, end)
                    except _Undecryptable as error:
                        raise TraceError(
                            f"segment {segment} of datagram {datagram} from {peer} does not decrypt at the "
                            f"segment size {segment_size} the first segment authenticated"
                        ) from error
            packets.append(self._commit(decrypted, timestamp_ns, datagram, segment, len(packets), position))
            position = decrypted.end
        return packets

    def _connection(self, local, peer, datagram: int, from_peer: bool, data: bytes, position: int) -> Connection:
        connections = self._current.get((local, peer), [])
        if not connections:
            raise TraceError(f"datagram {datagram} from {peer} has a short header before any Initial packet")
        candidates = []
        for connection in connections:
            receiver = SERVER if connection.sender(from_peer) == CLIENT else CLIENT
            if any(data[position + 1 : position + 1 + len(cid)] == cid for cid in connection.cids.get(receiver, ())):
                candidates.append(connection)
        if len(candidates) != 1:
            raise TraceError(
                f"datagram {datagram} from {peer} has a short header matching {len(candidates)} connections"
            )
        return candidates[0]

    def _long_connection(self, local, peer, from_peer: bool, dcid: bytes, scid: bytes) -> Connection | None:
        candidates = []
        for connection in self._current.get((local, peer), []):
            sender = connection.sender(from_peer)
            receiver = SERVER if sender == CLIENT else CLIENT
            if dcid in connection.cids.get(receiver, ()) or scid in connection.cids.get(sender, ()):
                candidates.append(connection)
        if len(candidates) > 1:
            raise TraceError(f"a long-header packet from {peer} matches more than one connection")
        return candidates[0] if candidates else None

    def _retry(self, local, peer, data: bytes, from_peer: bool, timestamp_ns: int) -> None:
        """Rekey a connection's Initial packets after a Retry (RFC 9001 section 5.2)."""

        reader = _Reader(data, 5)
        destination = reader.bytes(reader.byte())
        source = reader.bytes(reader.byte())
        connection = self._long_connection(local, peer, from_peer, destination, source)
        if connection is None or connection.sender(from_peer) != SERVER:
            raise TraceError(f"a Retry from {peer} does not belong to a connection")
        connection.cids.setdefault(SERVER, set()).add(source)
        # The client's next Initial is sent to the Retry's source connection ID,
        # which therefore keys the rest of the Initial space.
        connection.initial = initial_keys(source)
        connection.last_ns = timestamp_ns

    def _long(self, timestamp_ns: int, local, peer, from_peer: bool, data: bytes, position: int) -> _Decrypted:
        reader = _Reader(data, position)
        first = reader.byte()
        reader.bytes(4)
        dcid = reader.bytes(reader.byte())
        scid = reader.bytes(reader.byte())
        space = _LONG_TYPES[(first & 0x30) >> 4]
        if space == INITIAL:
            reader.bytes(reader.varint())
        length = reader.varint()
        packet_number_offset = reader.position
        end = packet_number_offset + length
        if end > len(data):
            raise TraceError(f"a long-header packet from {peer} extends past its datagram")

        connection = self._long_connection(local, peer, from_peer, dcid, scid)
        new_connection = False
        if space == INITIAL and connection is None:
            # A client Initial from a new source connection ID starts a new
            # connection on the address pair.
            connection = Connection(
                index=len(self.connections),
                local=local,
                peer=peer,
                client_is_peer=from_peer,
                client_scid=scid,
                initial=initial_keys(dcid),
                cids={SERVER: {dcid}},
                first_ns=timestamp_ns,
                last_ns=timestamp_ns,
            )
            new_connection = True
        elif connection is None:
            raise TraceError(f"a {space} packet from {peer} arrived before any Initial packet")
        sender = connection.sender(from_peer)
        keys = self._long_keys(connection, space, sender, peer)
        try:
            packet_number, payload = self._open(
                connection, keys, space, sender, data, position, packet_number_offset, end, 0x0F
            )
        except _Undecryptable as error:
            raise TraceError(f"a {space} packet from {peer} does not authenticate") from error
        return _Decrypted(
            space,
            packet_number,
            end,
            payload,
            sender,
            connection,
            new_connection,
            None,
            ((sender, scid),),
        )

    def _long_keys(self, connection: Connection, space: str, sender: str, peer) -> Keys:
        if space == INITIAL:
            return connection.initial[sender]
        if space == HANDSHAKE:
            keys = connection.handshake.get(sender)
        else:
            keys = connection.zero_rtt if sender == CLIENT else None
        if keys is None:
            raise TraceError(
                f"no key log secret decrypts the {space} packets of connection {connection.index} from {peer}"
            )
        return keys

    def _first_short(
        self, connection: Connection, from_peer: bool, data: bytes, position: int, datagram: int
    ) -> _Decrypted:
        """Decrypt a short-header packet whose segment end is unknown.

        The datagram's end is tried first. A GSO send instead holds later
        segments that can belong to different connections on one address pair.
        Each offset with a short-header form and a known Destination Connection
        ID is a candidate end, and authentication decides.
        """

        sender = connection.sender(from_peer)
        receiver = SERVER if sender == CLIENT else CLIENT
        dcid_length = connection.cid_length.get(receiver)
        if dcid_length is None:
            raise TraceError(f"connection {connection.index} sent a short header before its connection IDs were known")
        length = len(data)
        candidates = [length]
        # A socket can batch packets from several connections to the same
        # address pair. Any destination ID can mark the next GSO segment.
        cids = {
            cid
            for candidate in self._current[(connection.local, connection.peer)]
            for cid in candidate.cids.get(SERVER if candidate.sender(from_peer) == CLIENT else CLIENT, ())
        }
        for cid in cids:
            if cid:
                found = data.find(cid, position + 2)
                while found >= 0:
                    boundary = found - 1
                    # A short header's form bit is clear; its fixed bit may be greased.
                    if not data[boundary] & 0x80:
                        candidates.append(boundary)
                    found = data.find(cid, found + 1)
            else:
                # A zero-length ID gives no anchor, so try every possible end.
                candidates.extend(range(position + 21, length))
        for end in sorted(set(candidates), key=lambda value: (value != length, value)):
            try:
                return self._short(connection, from_peer, data, position, end)
            except _Undecryptable:
                continue
        raise TraceError(
            f"no segment boundary authenticates the short-header packet at byte {position} of datagram {datagram} "
            f"from {connection.peer}"
        )

    def _short(self, connection: Connection, from_peer: bool, data: bytes, position: int, end: int) -> _Decrypted:
        sender = connection.sender(from_peer)
        receiver = SERVER if sender == CLIENT else CLIENT
        packet_number_offset = position + 1 + connection.cid_length[receiver]
        generations = connection.generations.get(sender)
        if not generations:
            raise TraceError(f"no key log secret decrypts the 1-RTT packets of connection {connection.index}")
        current = connection.generation.get(sender, 0)
        # The key phase bit picks the generation; it is read after header
        # protection, which every generation shares.
        first, _, _ = self._unprotect(generations[0], data, position, packet_number_offset, end, 0x1F)
        phase = (first >> 2) & 1
        if phase == current % 2:
            order = [current, current - 2]
        else:
            order = [current + 1, current - 1]
        for generation in order:
            if generation < 0:
                continue
            while generation >= len(generations):
                generations.append(generations[-1].updated())
            try:
                packet_number, payload = self._open(
                    connection, generations[generation], DATA, sender, data, position, packet_number_offset, end, 0x1F
                )
            except _Undecryptable:
                continue
            return _Decrypted(DATA, packet_number, end, payload, sender, connection, False, generation, ())
        raise _Undecryptable()

    @staticmethod
    def _unprotect(keys: Keys, data: bytes, position: int, offset: int, end: int, bits: int) -> tuple[int, int, int]:
        sample = data[offset + 4 : offset + 20]
        if len(sample) != 16 or offset + 4 + 16 > end:
            raise _Undecryptable()
        mask = keys.mask(sample)
        first = data[position] ^ (mask[0] & bits)
        length = (first & 0x03) + 1
        truncated = int.from_bytes(
            bytes(a ^ b for a, b in zip(data[offset : offset + length], mask[1 : 1 + length], strict=True)), "big"
        )
        return first, length, truncated

    def _open(
        self,
        connection: Connection,
        keys: Keys,
        space: str,
        sender: str,
        data: bytes,
        position: int,
        offset: int,
        end: int,
        bits: int,
    ) -> tuple[int, bytes]:
        first, length, truncated = self._unprotect(keys, data, position, offset, end, bits)
        packet_number = decode_packet_number(truncated, length, connection.largest.get((sender, space)))
        header = bytes([first]) + data[position + 1 : offset] + truncated.to_bytes(length, "big")
        try:
            payload = keys.open(packet_number, header, data[offset + length : end])
        except InvalidTag as error:
            raise _Undecryptable() from error
        return packet_number, payload

    def _commit(
        self, decrypted: _Decrypted, timestamp_ns: int, datagram: int, segment: int, index: int, position: int
    ) -> Packet:
        connection = decrypted.connection
        if decrypted.new_connection:
            self.connections.append(connection)
            self._current.setdefault((connection.local, connection.peer), []).append(connection)
        connection.last_ns = timestamp_ns
        for endpoint, cid in decrypted.cids:
            connection.cids.setdefault(endpoint, set()).add(cid)
            length = len(cid)
            known = connection.cid_length.setdefault(endpoint, length)
            if known != length:
                raise TraceError(f"connection {connection.index} uses connection IDs of more than one length")
        key = (decrypted.sender, decrypted.space)
        connection.largest[key] = max(connection.largest.get(key, -1), decrypted.packet_number)
        if decrypted.generation is not None:
            connection.generation[decrypted.sender] = max(
                connection.generation.get(decrypted.sender, 0), decrypted.generation
            )
        try:
            frames = tuple(_frames(decrypted.payload, connection, decrypted.sender, decrypted.space))
        except _Malformed as error:
            raise TraceError(
                f"packet {decrypted.packet_number} of connection {connection.index} holds a malformed frame: {error}"
            ) from error
        if decrypted.space == INITIAL:
            self._read_hellos(connection, decrypted.sender)
        return Packet(
            timestamp_ns=timestamp_ns,
            connection=connection.index,
            sender=decrypted.sender,
            space=decrypted.space,
            packet_number=decrypted.packet_number,
            byte_length=decrypted.end - position,
            datagram=datagram,
            segment=segment,
            index=index,
            stream_frames=frames,
        )

    def _read_hellos(self, connection: Connection, sender: str) -> None:
        """Key the connection once its ClientHello and ServerHello are readable."""

        data = _contiguous(connection.crypto.get(sender, {}))
        if sender == CLIENT and connection.client_random is None and len(data) >= 38:
            if data[0] != 1:
                raise TraceError(f"connection {connection.index} does not open with a ClientHello")
            connection.client_random = bytes(data[6:38])
            secrets = self.secrets.get(connection.client_random)
            if secrets is None:
                raise TraceError(
                    f"no key log holds the secrets of connection {connection.index} from {connection.peer}"
                )
            connection.crypto.pop(CLIENT, None)
            self._key(connection)
        if sender == SERVER and connection.suite is None and len(data) >= 39:
            if data[0] != 2:
                raise TraceError(f"connection {connection.index} does not answer with a ServerHello")
            session_id_length = data[38]
            position = 39 + session_id_length
            if len(data) < position + 2:
                return
            suite = int.from_bytes(data[position : position + 2], "big")
            if suite not in SUITES:
                raise TraceError(f"connection {connection.index} negotiated cipher suite {suite:#06x}")
            connection.suite = SUITES[suite]
            connection.crypto.pop(SERVER, None)
            self._key(connection)

    def _key(self, connection: Connection) -> None:
        if connection.suite is None or connection.client_random is None:
            return
        secrets = self.secrets[connection.client_random]
        for label, (space, sender) in _SECRETS.items():
            secret = secrets.get(label)
            if secret is None:
                continue
            keys = Keys(connection.suite, secret)
            if space == HANDSHAKE:
                connection.handshake[sender] = keys
            elif space == ZERO_RTT:
                connection.zero_rtt = keys
            else:
                connection.generations[sender] = [keys]


def _contiguous(pieces: Mapping[int, bytes]) -> bytes:
    """Join CRYPTO pieces from offset 0 up to the first gap."""

    data = bytearray()
    while True:
        extended = False
        for offset, piece in pieces.items():
            if offset <= len(data) < offset + len(piece):
                data.extend(piece[len(data) - offset :])
                extended = True
        if not extended:
            return bytes(data)


def _frames(payload: bytes, connection: Connection, sender: str, space: str) -> Iterator[StreamFrame]:
    """Parse every frame of a payload and yield its STREAM frames.

    CRYPTO frames of the Initial space are kept until the hellos are read, and
    NEW_CONNECTION_ID frames are checked for a consistent length. An unknown
    frame type is an error, because its length cannot be known and every frame
    after it would be misread.
    """

    reader = _Reader(payload)
    if not payload:
        raise _Malformed("empty payload")
    while reader.remaining():
        frame_type = reader.varint()
        if frame_type == 0x00:
            continue
        if frame_type in (0x01, 0x1E, 0x1F):
            continue
        if frame_type in (0x02, 0x03):
            reader.varint()
            reader.varint()
            ranges = reader.varint()
            reader.varint()
            for _ in range(ranges):
                reader.varint()
                reader.varint()
            if frame_type == 0x03:
                for _ in range(3):
                    reader.varint()
        elif frame_type == 0x04:
            for _ in range(3):
                reader.varint()
        elif frame_type == 0x05:
            reader.varint()
            reader.varint()
        elif frame_type == 0x06:
            offset = reader.varint()
            data = reader.bytes(reader.varint())
            unread = connection.client_random is None if sender == CLIENT else connection.suite is None
            if space == INITIAL and unread:
                pieces = connection.crypto.setdefault(sender, {})
                if offset < 4096:
                    pieces[offset] = data
        elif frame_type == 0x07:
            reader.bytes(reader.varint())
        elif 0x08 <= frame_type <= 0x0F:
            stream_id = reader.varint()
            offset = reader.varint() if frame_type & 0x04 else 0
            length = reader.varint() if frame_type & 0x02 else reader.remaining()
            reader.bytes(length)
            yield StreamFrame(stream_id, offset, offset + length, bool(frame_type & 0x01))
        elif frame_type in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):
            reader.varint()
        elif frame_type in (0x11, 0x15):
            reader.varint()
            reader.varint()
        elif frame_type == 0x18:
            reader.varint()
            reader.varint()
            length = reader.byte()
            cid = reader.bytes(length)
            reader.bytes(16)
            connection.cids.setdefault(sender, set()).add(cid)
            # The connection ID belongs to the frame's sender: packets sent to
            # it carry this length.
            known = connection.cid_length.get(sender)
            if known is not None and known != length:
                raise TraceError(f"connection {connection.index} issues connection IDs of more than one length")
        elif frame_type in (0x1A, 0x1B):
            reader.bytes(8)
        elif frame_type == 0x1C:
            reader.varint()
            reader.varint()
            reader.bytes(reader.varint())
        elif frame_type == 0x1D:
            reader.varint()
            reader.bytes(reader.varint())
        elif frame_type == 0x30:
            reader.bytes(reader.remaining())
        elif frame_type == 0x31:
            reader.bytes(reader.varint())
        elif frame_type == 0xAF:
            # ACK_FREQUENCY (draft-ietf-quic-ack-frequency), as both Quinn and
            # Google QUICHE encode it.
            for _ in range(4):
                reader.varint()
        elif frame_type == 0x24:
            # RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset).
            for _ in range(4):
                reader.varint()
        else:
            raise _Malformed(f"unknown frame type {frame_type:#x}")
