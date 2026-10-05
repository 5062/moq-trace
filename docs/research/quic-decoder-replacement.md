# QUIC decoder replacement feasibility

Investigated 2026-10-04 against upstream source and the local capture contract.
The question is whether replacing `python/src/moq_trace/quic.py` removes a
substantial responsibility while preserving independent packet and STREAM
validation. Production code and dependencies are unchanged by this research.

## Required behavior

The local [capture design](../specs/2026-10-03-pcap-decryption-design.md) and
`quic.py` require NSS key-log loading, TLS hello reassembly, QUIC v1 packet
numbers and lengths, STREAM IDs and half-open ranges, strict rejection of
undecodable packets or unknown frames, greased fixed bits, and authenticated
GSO boundaries without captured segment-size metadata. Key generations are
committed only after authentication, and older generations remain usable for
reordered packets. Wire correlation and coverage in `wire.py` remain required
regardless of which library decrypts packets.

## Source findings

### Wireshark and tshark

Wireshark v4.6.8, the release tested locally, does have GSO support.
`quic_get_message_tvb` finds the first
repeated DCID and immediately chooses the preceding byte as a boundary. It does
not try authenticated alternatives, enforce equal segment sizes, or support
zero-length DCIDs through this heuristic. The default minimum DCID length is
eight. Greased fixed bits are supported. Two phase ciphers retain limited
reordered key-update history; updates commit after authentication. Unknown
frames and decryption failures produce expert diagnostics, not analyzer errors.
These are source findings, not capture-test results.
[Wireshark v4.6.8 QUIC source](https://github.com/wireshark/wireshark/blob/v4.6.8/epan/dissectors/packet-quic.c#L4519-L4564).
The same heuristic remains in inspected
[upstream master](https://github.com/wireshark/wireshark/blob/341bd0ba15987bfab1441b6116c2e484b898504e/epan/dissectors/packet-quic.c#L4935-L4980).

The display-field contract exposes packet numbers and lengths, STREAM IDs,
offsets, lengths and FIN, plus unknown-frame and decryption diagnostics.
[QUIC field reference](https://www.wireshark.org/docs/dfref/q/quic.html).

In v4.6.8, unknown frames are `quic.ft.unknown` notes, and decryption failures
are `quic.decryption_failed` warnings. Missing packet-number context can return
without diagnostics. Require positive evidence of decrypted frames and a packet number as well as checking
errors. STREAM offsets default to zero when omitted; implicit lengths are not
emitted as `quic.stream.length`, but the always-added `quic.stream_data` field
records the decoded byte extent, available as its PDML size. Per-frame nesting
is provided by `quic.frame`.
[Versioned parsing and field source](https://github.com/wireshark/wireshark/blob/v4.6.8/epan/dissectors/packet-quic.c#L2631-L2695).

`tshark` offers JSON and PDML output. A replacement adapter must preserve each
coalesced packet and each individual frame, rather than flattening repeated
field values into unrelated columns. It must also check every eligible capture
record and reject missing decryption or malformed/unknown frames; a successful
process exit is insufficient evidence of complete decoding. This adapter
requirement is an inference from the analyzer contract and the available output
formats. [tshark manual](https://www.wireshark.org/docs/man-pages/tshark.html).

The original design's blanket claim that tshark cannot split GSO sends is
therefore outdated. The narrower authenticated-boundary requirement remains
unsatisfied by the inspected heuristic. Successful real captures alone cannot
prove this distinction harmless.

### aioquic

The documented API is an endpoint state machine driven by received datagrams,
timers and application writes. Its configuration's secrets log is an output
stream; the documented API does not provide passive NSS key-log import or a
bidirectional pcap decoder. [QUIC API](https://aioquic.readthedocs.io/en/latest/quic.html).
The first-party [design](https://aioquic.readthedocs.io/en/latest/design.html)
defines Sans-IO as leaving actual I/O operations to the caller, not passive
analysis. The [configuration source](https://github.com/aiortc/aioquic/blob/6d36838d008c2202c337142fa07e8bf80e96bac8/src/aioquic/quic/configuration.py#L69-L74)
explicitly describes secrets logging as producing material for Wireshark.
Taken together with the endpoint methods, this supports the distinction
between an embeddable transport endpoint and a capture decoder.

The endpoint implementation catches unavailable-key and cryptographic errors,
logs packet drops and continues. STREAM parsing is coupled to direction checks,
flow control and stream reassembly. The frame-handler map omits the locally
required ACK_FREQUENCY, IMMEDIATE_ACK and RESET_STREAM_AT extensions. These
choices make driving `QuicConnection.receive_datagram` a poor replacement for
strict passive validation.
[aioquic connection source](https://github.com/aiortc/aioquic/blob/6d36838d008c2202c337142fa07e8bf80e96bac8/src/aioquic/quic/connection.py).

`pull_quic_header` rejects packets whose fixed bit is zero, including short
headers. Its short-header length extends through the supplied buffer, so GSO
boundary recovery would still be ours.
[aioquic packet source](https://github.com/aiortc/aioquic/blob/6d36838d008c2202c337142fa07e8bf80e96bac8/src/aioquic/quic/packet.py).

`CryptoContext.decrypt_packet` returns header, plaintext, reconstructed packet
number and a key-update flag without committing an update. This supports
failed boundary trials. `CryptoPair` commits updates to both directions and
retains no previous generation. A passive adapter would retain contexts per
direction and generation. `next_key_phase` builds a context with newly derived
header protection, while `apply_key_phase` intentionally keeps the original
header protection; a retained-context adapter must preserve that invariant.
[aioquic crypto source](https://github.com/aiortc/aioquic/blob/6d36838d008c2202c337142fa07e8bf80e96bac8/src/aioquic/quic/crypto.py).

## Assessment

Replacing only cryptographic primitives might remove roughly one hundred
existing lines before adapter code, but leaves key-log association, hello
reassembly, GSO discovery, connection state, generation selection and frame
parsing. It adds an endpoint-library dependency and coupling to undocumented
crypto internals. This is a local code-size estimate and engineering inference,
not a measured prototype reduction. It does not establish a substantial
maintenance saving.

The local experiments below confirm tshark as a useful independent cross-check,
but rule out an unmodified replacement under the current acceptance contract.
A complete replacement would need authenticated GSO boundary recovery as well
as strict diagnostic checks and metadata extraction. This no longer delegates
the whole decryption responsibility to a small adapter. Reducing wire-validation
scope would instead change a measurement requirement.

Recommendation: retain the current decoder. Do not add aioquic for a partial
crypto substitution. Revisit tshark if its upstream GSO implementation gains
authenticated boundary recovery, including zero-length connection IDs, and the
same packet/frame comparisons and valid boundary-collision fixture pass.

## Local experiments

These are observations from this workspace, separate from the source review.
The tested tool was TShark 4.6.8, Git commit `e677bf052328`, obtained temporarily
from the repository's pinned Nixpkgs input. No production dependency was added.

### Retained captures

All three captures under `artifacts/bench-20261004T174613Z` were compared against
the current decoder. The input was each relay's full `relay.pcap`, using both
peer key logs named by its `network.json`. The comparison filtered the same
loopback duplicates and relay port as `pcap.read_datagrams`.

| Relay | Eligible datagrams | GSO datagrams | Decrypted packets | Exact matches |
|---|---:|---:|---:|---:|
| Google QUICHE | 19,671 | 1,345 | 28,411 | 28,411 |
| Cloudflare moq-rs | 6,748 | 3,856 | 23,072 | 23,072 |
| moq-dev/moq | 4,133 | 2,697 | 21,661 | 21,661 |

Equality was checked as an unordered multiset of packet records containing:

- Nanosecond realtime timestamp, local/peer addresses and ports, and direction.
- Packet number space, expanded packet number, and encoded packet byte length.
- Every STREAM frame's stream ID, half-open range, and FIN flag, in packet order.

This comparison did not establish equivalence of connection numbering,
`segment`, or `packet_index`, nor rebuild and compare final analysis artifacts.
It is a feasibility check of decoding, rather than an integration acceptance
suite. Real captures alone do not establish support for every required input.

`tshark -T pdml` preserved per-packet and per-frame nesting. Its
`quic.protected_payload` field was present on successfully decrypted packets,
so it is not an error indicator. Decrypted `quic.frame` records, packet numbers,
`quic.decryption_failed`, `quic.ft.unknown`, and malformed diagnostics are the
relevant checks. STREAM offset and length fields are sometimes omitted; offset
defaults to zero and implicit length comes from `quic.stream_data`'s PDML size.

### Authenticated GSO boundary collision

A generated capture reused the first seven eligible datagrams of the retained
Google capture, establishing a real handshake and its keys. It then added one
server datagram containing two valid 1,200-byte packets, numbered 7 and 8, each
carrying a STREAM frame on stream 4. The control capture decoded successfully
in both implementations.

The second capture changed only the first packet's application bytes so its
ciphertext contained a short-header-form byte followed by the destination
connection ID at byte 100, before the true boundary at byte 1,200. AES-GCM's
plaintext/ciphertext XOR relation allowed placing this sequence inside STREAM
data, and the modified packet was then encrypted and authenticated normally.
The second segment was unchanged. This creates a valid input with a false
heuristic boundary, rather than a corrupt packet.

| Result | Current decoder | TShark 4.6.8 |
|---|---|---|
| Control GSO datagram | Packets 7 and 8; both STREAM frames | Same packets and frames |
| Valid boundary-collision datagram | Packets 7 and 8; both STREAM frames | False split; two authentication failures; only packet 8 has decoded frames |
| Boundary-collision process exit | Successful decode | Exit status 0 despite the failures |

The tshark output exposed three apparent packet numbers: 7, 1116414541, and 8.
The first two had no decoded frames and reported authentication failures. The
current decoder tried the false boundary, rejected it by authentication, then
accepted the actual 1,200-byte boundary and recovered both frames.

A strict adapter could reject this tshark output, but that would reject a valid
capture that the current decoder accepts. Authentication failure here does not
establish a defective capture: the external heuristic chose the wrong boundary.
An adapter would need to recover and retry boundaries, not merely turn warnings
into errors.

### Experiment artifacts and reproduction

The local probes and their machine-readable results are retained under
`target/quic-decoder-spike/`, which is ignored by Git:

- `compare.py`, the PDML/current-decoder packet multiset comparison.
- `google-quiche.json`, `cloudflare-moq-rs.json`, and `moq-dev-moq.json`.
- `boundary.py`, the generated control/collision capture probe.
- `boundary-results.json` and the two generated `.pcap` files.

Merged key logs remain local in that ignored directory. They are not part of
this research note or committed artifacts. The retained captures and probe
scripts are workspace evidence, not portable fixtures available in a fresh
checkout.

The temporary tool can be reproduced from this checkout's Nix inputs:

```sh
nix develop --command nix shell --inputs-from . nixpkgs#wireshark-cli --command tshark --version
```

The capture probe used the following tshark arguments, with absolute key-log
paths and each manifest's relay port:

```text
tshark -n -r relay.pcap -o tls.keylog_file:merged.keys -d udp.port==4443,quic -T pdml
```

After provisioning tshark, the local scripts run through the development shell:

```sh
nix develop --command python target/quic-decoder-spike/compare.py
nix develop --command python target/quic-decoder-spike/boundary.py
```

The scripts record the exact Nix-store binary used here. Another environment
must update that path to the tshark provided by its pinned Nixpkgs input.
