"""Decrypt QUIC packets: RFC 9001 vectors, then synthetic captures."""

from __future__ import annotations

import os
import pathlib
import sys
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace.decode import quic  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402

# RFC 9001 appendix A.
_DCID = bytes.fromhex("8394c8f03e515708")
_CLIENT_INITIAL = bytes.fromhex(
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
    "e221af44860018ab0856972e194cd934"
)
_SERVER_INITIAL = bytes.fromhex(
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
    "2158407dd074ee"
)
_CLIENT_RANDOM = bytes.fromhex("ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c")

LOCAL = ("10.0.0.1", 4443)
PEER = ("10.0.0.2", 50266)


class RfcVectorTests(unittest.TestCase):
    def test_initial_keys(self) -> None:
        keys = quic.initial_keys(_DCID)
        self.assertEqual(keys[quic.CLIENT].key.hex(), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(keys[quic.CLIENT].iv.hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(keys[quic.CLIENT].hp.hex(), "9f50449e04a0e810283a1e9933adedd2")
        self.assertEqual(keys[quic.SERVER].key.hex(), "cf3a5331653c364c88f0f379b6067e37")
        self.assertEqual(keys[quic.SERVER].iv.hex(), "0ac1493ca1905853b0bba03e")
        self.assertEqual(keys[quic.SERVER].hp.hex(), "c206b8d9b9f0f37644430b490eeaa314")

    def test_client_and_server_initial_packets(self) -> None:
        decryptor = quic.Decryptor({_CLIENT_RANDOM: {}})
        (client,) = decryptor.datagram(1, LOCAL, PEER, True, _CLIENT_INITIAL)
        self.assertEqual((client.sender, client.space, client.packet_number), ("client", "initial", 2))
        self.assertEqual(client.byte_length, len(_CLIENT_INITIAL))
        connection = decryptor.connections[0]
        self.assertEqual(connection.client_random, _CLIENT_RANDOM)

        (server,) = decryptor.datagram(2, LOCAL, PEER, False, _SERVER_INITIAL)
        self.assertEqual((server.sender, server.space, server.packet_number), ("server", "initial", 1))
        self.assertEqual(connection.suite, quic.SUITES[0x1301])
        self.assertEqual(connection.cid_length, {"client": 0, "server": 8})

    def test_chacha20_short_header_packet(self) -> None:
        secret = bytes.fromhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
        keys = quic.Keys(quic.SUITES[0x1303], secret)
        self.assertEqual(keys.key.hex(), "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
        self.assertEqual(keys.iv.hex(), "e0459b3474bdd0e44a41c144")
        self.assertEqual(keys.hp.hex(), "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        self.assertEqual(
            keys.updated().secret.hex(), "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"
        )
        packet = bytes.fromhex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
        first, length, truncated = quic.Decryptor._unprotect(keys, packet, 0, 1, len(packet), 0x1F)
        self.assertEqual((first, length, truncated), (0x42, 3, 0x00BFF4))
        number = quic.decode_packet_number(truncated, length, 654_360_563)
        self.assertEqual(number, 654_360_564)
        header = bytes([first]) + truncated.to_bytes(length, "big")
        self.assertEqual(keys.open(number, header, packet[4:]), b"\x01")


def _varint(value: int) -> bytes:
    for length, prefix in ((1, 0x00), (2, 0x40), (4, 0x80), (8, 0xC0)):
        if value < 1 << (8 * length - 2):
            return (value | (prefix << (8 * length - 8))).to_bytes(length, "big")
    raise ValueError(value)


def _stream(stream_id: int, offset: int, data: bytes, fin: bool = False) -> bytes:
    return bytes([0x0E | fin]) + _varint(stream_id) + _varint(offset) + _varint(len(data)) + data


def _crypto(offset: int, data: bytes) -> bytes:
    return b"\x06" + _varint(offset) + _varint(len(data)) + data


class _Peer:
    """Build the protected packets a client and server exchange, as a capture holds them."""

    def __init__(self, seed: int = 1, client_cid: bytes = b"cccccccc", server_cid: bytes = b"ssssssss") -> None:
        self.random = os.urandom(32) if seed is None else bytes([seed]) * 32
        self.dcid = bytes([seed]) * 8
        self.client_cid = client_cid
        self.server_cid = server_cid
        self.initial = quic.initial_keys(self.dcid)
        suite = quic.SUITES[0x1301]
        self.secrets = {
            label: bytes([seed, index]) * 16
            for index, label in enumerate(
                (
                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                    "CLIENT_TRAFFIC_SECRET_0",
                    "SERVER_TRAFFIC_SECRET_0",
                )
            )
        }
        self.handshake = {
            quic.CLIENT: quic.Keys(suite, self.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]),
            quic.SERVER: quic.Keys(suite, self.secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]),
        }
        self.data = {
            quic.CLIENT: [quic.Keys(suite, self.secrets["CLIENT_TRAFFIC_SECRET_0"])],
            quic.SERVER: [quic.Keys(suite, self.secrets["SERVER_TRAFFIC_SECRET_0"])],
        }

    def key_log(self) -> dict[bytes, dict[str, bytes]]:
        return {self.random: dict(self.secrets)}

    def client_hello(self) -> bytes:
        body = b"\x03\x03" + self.random + b"\x00" * 40
        return b"\x01" + len(body).to_bytes(3, "big") + body

    @staticmethod
    def server_hello() -> bytes:
        body = b"\x03\x03" + b"\x22" * 32 + b"\x00" + b"\x13\x01" + b"\x00" * 10
        return b"\x02" + len(body).to_bytes(3, "big") + body

    @staticmethod
    def _protect(keys: quic.Keys, header: bytes, offset: int, number: int, payload: bytes, bits: int) -> bytes:
        length = (header[0] & 0x03) + 1
        payload = payload + b"\x00" * max(0, 4 - length - len(payload))
        sealed = keys.seal(number, header, payload)
        sample = sealed[4 - length : 20 - length]
        mask = keys.mask(sample)
        first = header[0] ^ (mask[0] & bits)
        protected = bytes(a ^ b for a, b in zip(header[offset:], mask[1 : 1 + length], strict=True))
        return bytes([first]) + header[1:offset] + protected + sealed

    def long(self, sender: str, space: str, number: int, payload: bytes) -> bytes:
        keys = self.initial[sender] if space == "initial" else self.handshake[sender]
        types = {"initial": 0, "handshake": 2}
        dcid = (self.dcid if sender == quic.CLIENT else self.client_cid) if space == "initial" else None
        if dcid is None:
            dcid = self.server_cid if sender == quic.CLIENT else self.client_cid
        scid = self.client_cid if sender == quic.CLIENT else self.server_cid
        header = bytes([0xC0 | types[space] << 4 | 0x01]) + quic.VERSION_1.to_bytes(4, "big")
        header += bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        if space == "initial":
            header += b"\x00"
        payload = payload + b"\x00" * max(0, 20 - len(payload))
        header += (0x4000 | (2 + len(payload) + 16)).to_bytes(2, "big")
        offset = len(header)
        header += (number & 0xFFFF).to_bytes(2, "big")
        return self._protect(keys, header, offset, number, payload, 0x0F)

    def short(
        self,
        sender: str,
        number: int,
        payload: bytes,
        generation: int = 0,
        size: int | None = None,
        grease: bool = False,
    ) -> bytes:
        """A 1-RTT packet, padded to exactly `size` bytes as a full GSO segment is."""

        if size is not None:
            dcid = self.server_cid if sender == quic.CLIENT else self.client_cid
            payload += b"\x00" * (size - (1 + len(dcid) + 2 + len(payload) + 16))
        generations = self.data[sender]
        while generation >= len(generations):
            generations.append(generations[-1].updated())
        dcid = self.server_cid if sender == quic.CLIENT else self.client_cid
        # RFC 9287 lets a sender clear the fixed bit once its peer allows it.
        header = bytes([(0x00 if grease else 0x40) | (generation % 2) << 2 | 0x01]) + dcid
        offset = len(header)
        header += (number & 0xFFFF).to_bytes(2, "big")
        return self._protect(generations[generation], header, offset, number, payload, 0x1F)

    def handshake_datagrams(self) -> list[tuple[bool, bytes]]:
        """The handshake as `(from_peer, datagram)`; the peer is the client."""

        client_initial = self.long(quic.CLIENT, "initial", 0, _crypto(0, self.client_hello()) + b"\x00" * 1000)
        server = self.long(quic.SERVER, "initial", 0, _crypto(0, self.server_hello()))
        server += self.long(quic.SERVER, "handshake", 0, _crypto(0, b"\x08" + b"\x00" * 40))
        client_handshake = self.long(quic.CLIENT, "handshake", 0, _crypto(0, b"\x14" + b"\x00" * 40))
        return [(True, client_initial), (False, server), (True, client_handshake)]


def _decrypt(decryptor: quic.Decryptor, datagrams, start: int = 0, peer=PEER) -> list[quic.Packet]:
    packets = []
    for offset, (from_peer, payload) in enumerate(datagrams):
        packets.extend(decryptor.datagram(start + offset, LOCAL, peer, from_peer, payload))
    return packets


class DecryptorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.peer = _Peer()
        self.decryptor = quic.Decryptor(self.peer.key_log())
        self.handshake = _decrypt(self.decryptor, self.peer.handshake_datagrams())

    def test_four_connections_share_one_udp_address_pair(self) -> None:
        peers = [_Peer(seed=i, client_cid=bytes([i]) * 8, server_cid=bytes([i + 4]) * 8) for i in range(1, 5)]
        decryptor = quic.Decryptor(quic.merge_key_logs(peer.key_log() for peer in peers))
        for stage in range(3):
            for index, peer in enumerate(peers):
                packets = _decrypt(decryptor, [peer.handshake_datagrams()[stage]])
                self.assertTrue(all(packet.connection == index for packet in packets))
        for index, peer in enumerate(peers):
            for sender in (quic.CLIENT, quic.SERVER):
                packets = _decrypt(decryptor, [(sender == quic.CLIENT, peer.short(sender, 1, _stream(4, 0, b"data")))])
                self.assertEqual(packets[0].connection, index)
        self.assertEqual(len(decryptor.connections), 4)
        for index, peer in enumerate(peers):
            cid = bytes([index + 10]) * 8
            frame = b"\x18\x00\x00\x08" + cid + b"\x00" * 16
            (packet,) = _decrypt(decryptor, [(False, peer.short(quic.SERVER, 2, frame))])
            self.assertEqual(packet.connection, index)
            peer.server_cid = cid
        # One socket can batch segments from different connections to the same peer.
        payload = b"".join(peer.short(quic.CLIENT, 2, _stream(4, 4, b"next"), size=1200) for peer in peers)
        packets = decryptor.datagram(10, LOCAL, PEER, True, payload)
        self.assertEqual([(packet.connection, packet.segment) for packet in packets], list(enumerate(range(4))))

    def test_handshake_coalesces_and_keys_every_space(self) -> None:
        self.assertEqual(
            [
                (packet.sender, packet.space, packet.packet_number, packet.datagram, packet.index)
                for packet in self.handshake
            ],
            [
                ("client", "initial", 0, 0, 0),
                ("server", "initial", 0, 1, 0),
                ("server", "handshake", 0, 1, 1),
                ("client", "handshake", 0, 2, 0),
            ],
        )

    def test_gso_send_splits_at_the_authenticated_segment_size(self) -> None:
        segments = [
            self.peer.short(quic.SERVER, number, _stream(4, number * 1100, b"x" * 1100), size=1200)
            for number in range(3)
        ]
        tail = self.peer.short(quic.SERVER, 3, _stream(4, 3300, b"y" * 300, fin=True))
        self.assertEqual(len({len(segment) for segment in segments}), 1)
        packets = self.decryptor.datagram(10, LOCAL, PEER, False, b"".join(segments) + tail)
        self.assertEqual([packet.segment for packet in packets], [0, 1, 2, 3])
        self.assertEqual([packet.packet_number for packet in packets], [0, 1, 2, 3])
        self.assertEqual(
            [frame for packet in packets for frame in packet.stream_frames],
            [
                quic.StreamFrame(4, 0, 1100, False),
                quic.StreamFrame(4, 1100, 2200, False),
                quic.StreamFrame(4, 2200, 3300, False),
                quic.StreamFrame(4, 3300, 3600, True),
            ],
        )
        self.assertEqual([packet.byte_length for packet in packets[:3]], [len(segments[0])] * 3)

    def test_gso_boundary_is_chosen_by_authentication_not_by_a_repeated_connection_id(self) -> None:
        # A decoder that cuts at the first repeat of the destination connection
        # ID splits this valid send at the wrong place, because the first
        # segment carries that ID inside its own STREAM data. Wireshark's
        # heuristic does this and still exits successfully, so only a decoder
        # that lets authentication pick the boundary recovers both packets.
        cid = self.peer.client_cid
        size = 1200
        header_size = 1 + len(cid) + 2
        plain = _stream(4, 0, b"x" * 1100)
        plain += b"\x00" * (size - header_size - 16 - len(plain))
        ordinary = self.peer.short(quic.SERVER, 0, plain, size=size)
        # AES-GCM ciphertext is the plaintext XOR a keystream fixed by the key and
        # packet number, so choosing the plaintext chooses the ciphertext. The
        # packet is then sealed normally and authenticates.
        false_boundary = 100
        forged = b"\x40" + cid
        changed = bytearray(plain)
        for offset, value in enumerate(forged, start=false_boundary):
            changed[offset - header_size] ^= ordinary[offset] ^ value
        collision = self.peer.short(quic.SERVER, 0, bytes(changed), size=size)
        self.assertEqual(len(collision), size)
        self.assertEqual(collision[false_boundary : false_boundary + len(forged)], forged)
        second = self.peer.short(quic.SERVER, 1, _stream(4, 1100, b"y" * 1100), size=size)

        packets = self.decryptor.datagram(10, LOCAL, PEER, False, collision + second)
        self.assertEqual([(packet.segment, packet.packet_number) for packet in packets], [(0, 0), (1, 1)])
        self.assertEqual([packet.byte_length for packet in packets], [size, size])
        self.assertEqual(
            [frame for packet in packets for frame in packet.stream_frames],
            [quic.StreamFrame(4, 0, 1100, False), quic.StreamFrame(4, 1100, 2200, False)],
        )

    def test_greased_fixed_bits_still_split_and_decrypt(self) -> None:
        segments = [
            self.peer.short(quic.SERVER, number, _stream(4, number * 1100, b"x" * 1100), size=1200, grease=True)
            for number in range(3)
        ]
        packets = self.decryptor.datagram(10, LOCAL, PEER, False, b"".join(segments))
        self.assertEqual([packet.segment for packet in packets], [0, 1, 2])
        self.assertTrue(all(segment[0] & 0x40 == 0 for segment in segments))

    def test_zero_padding_after_a_long_header_packet_is_skipped(self) -> None:
        # A short header runs to the end of its datagram, so only a long-header
        # packet, which states its length, can be followed by padding.
        packet = self.peer.long(quic.SERVER, "handshake", 1, b"\x01")
        (decrypted,) = self.decryptor.datagram(10, LOCAL, PEER, False, packet + b"\x00" * 40)
        self.assertEqual(decrypted.byte_length, len(packet))

    def test_segment_size_may_change_between_sends(self) -> None:
        big = [
            self.peer.short(quic.CLIENT, number, _stream(0, number * 1100, b"a" * 1100), size=1200)
            for number in range(2)
        ]
        small = [
            self.peer.short(quic.CLIENT, number, _stream(0, number * 500, b"b" * 500), size=600)
            for number in range(2, 5)
        ]
        first = self.decryptor.datagram(10, LOCAL, PEER, True, b"".join(big))
        second = self.decryptor.datagram(11, LOCAL, PEER, True, b"".join(small))
        self.assertEqual([packet.segment for packet in first + second], [0, 1, 0, 1, 2])

    def test_a_single_packet_datagram_is_not_split(self) -> None:
        # The payload repeats the DCID with a short-header byte before it, which
        # must not be taken for a segment boundary.
        payload = _stream(0, 0, b"\x41" + self.peer.server_cid + b"z" * 200)
        (packet,) = self.decryptor.datagram(10, LOCAL, PEER, True, self.peer.short(quic.CLIENT, 0, payload))
        self.assertEqual(packet.stream_frames[0].offset_end, 209)

    def test_key_update_moves_to_the_next_generation(self) -> None:
        datagrams = [
            (False, self.peer.short(quic.SERVER, 0, b"\x01")),
            (False, self.peer.short(quic.SERVER, 1, b"\x01", generation=1)),
            (False, self.peer.short(quic.SERVER, 2, b"\x01", generation=1)),
            (False, self.peer.short(quic.SERVER, 3, b"\x01", generation=2)),
        ]
        packets = _decrypt(self.decryptor, datagrams, 10)
        self.assertEqual([packet.packet_number for packet in packets], [0, 1, 2, 3])
        self.assertEqual(self.decryptor.connections[0].generation["server"], 2)

    def test_packet_numbers_expand_past_their_encoding(self) -> None:
        datagrams = [
            (False, self.peer.short(quic.SERVER, number, b"\x01")) for number in (65_534, 65_535, 65_536, 65_537)
        ]
        packets = _decrypt(self.decryptor, datagrams, 10)
        self.assertEqual([packet.packet_number for packet in packets], [65_534, 65_535, 65_536, 65_537])

    def test_a_new_client_connection_id_starts_a_new_connection(self) -> None:
        other = _Peer(seed=2, client_cid=b"dddddddd", server_cid=b"tttttttt")
        self.decryptor.secrets = {**self.peer.key_log(), **other.key_log()}
        _decrypt(self.decryptor, other.handshake_datagrams(), 20)
        (packet,) = self.decryptor.datagram(30, LOCAL, PEER, False, other.short(quic.SERVER, 0, b"\x01"))
        self.assertEqual(packet.connection, 1)
        self.assertEqual(len(self.decryptor.connections), 2)

    def test_a_client_hello_split_across_initial_packets(self) -> None:
        peer = _Peer(seed=3)
        hello = peer.client_hello()
        first = peer.long(quic.CLIENT, "initial", 0, _crypto(0, hello[:20]) + b"\x00" * 600)
        second = peer.long(quic.CLIENT, "initial", 1, _crypto(20, hello[20:]) + b"\x00" * 600)
        decryptor = quic.Decryptor(peer.key_log())
        _decrypt(decryptor, [(True, first), (True, second)])
        self.assertEqual(decryptor.connections[0].client_random, peer.random)

    def test_a_connection_without_key_log_secrets_is_an_error(self) -> None:
        decryptor = quic.Decryptor({})
        with self.assertRaisesRegex(TraceError, "no key log holds the secrets of connection 0"):
            _decrypt(decryptor, _Peer(seed=4).handshake_datagrams()[:1])

    def test_an_unknown_frame_type_is_an_error(self) -> None:
        with self.assertRaisesRegex(TraceError, "unknown frame type 0x21"):
            self.decryptor.datagram(10, LOCAL, PEER, False, self.peer.short(quic.SERVER, 0, b"\x21\x00"))

    def test_a_segment_that_does_not_decrypt_is_an_error(self) -> None:
        segments = [
            self.peer.short(quic.SERVER, number, _stream(4, number * 1100, b"x" * 1100), size=1200)
            for number in range(3)
        ]
        corrupt = bytearray(b"".join(segments))
        corrupt[-5] ^= 0xFF
        with self.assertRaisesRegex(TraceError, "segment 2 of datagram 3 .* does not decrypt"):
            self.decryptor.datagram(10, LOCAL, PEER, False, bytes(corrupt))

    def test_a_short_header_without_a_connection_is_an_error(self) -> None:
        with self.assertRaisesRegex(TraceError, "short header before any Initial packet"):
            self.decryptor.datagram(10, LOCAL, ("10.0.0.9", 1), True, self.peer.short(quic.CLIENT, 0, b"\x01"))


class KeyLogTests(unittest.TestCase):
    def test_reads_quic_secrets_and_ignores_other_labels(self) -> None:
        random = "11" * 32
        lines = [
            "# comment",
            f"CLIENT_TRAFFIC_SECRET_0 {random} {'aa' * 32}",
            f"EXPORTER_SECRET {random} {'bb' * 32}",
            f"CLIENT_RANDOM {random} {'cc' * 48}",
        ]
        self.assertEqual(
            quic.read_key_log(lines), {bytes.fromhex(random): {"CLIENT_TRAFFIC_SECRET_0": bytes.fromhex("aa" * 32)}}
        )

    def test_conflicting_secrets_are_an_error(self) -> None:
        random = "11" * 32
        first = quic.read_key_log([f"CLIENT_TRAFFIC_SECRET_0 {random} {'aa' * 32}"])
        second = quic.read_key_log([f"CLIENT_TRAFFIC_SECRET_0 {random} {'bb' * 32}"])
        with self.assertRaisesRegex(TraceError, "two different CLIENT_TRAFFIC_SECRET_0 secrets"):
            quic.merge_key_logs([first, second])

    def test_malformed_lines_are_an_error(self) -> None:
        with self.assertRaisesRegex(TraceError, "line 1 is not"):
            quic.read_key_log(["CLIENT_TRAFFIC_SECRET_0 only-two"])


if __name__ == "__main__":
    unittest.main()
