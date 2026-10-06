"""The TLS certificate a relay is started with when its arguments ask for one."""

from __future__ import annotations

import datetime
import ipaddress
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .config import ExperimentConfig

# The files a relay argument placeholder refers to, in the run directory.
CERTIFICATE = "relay.crt"
KEY = "relay.key"


def needs_certificate(config: ExperimentConfig) -> bool:
    """Report whether the relay arguments name the certificate or its key."""

    return any(placeholder in argument for argument in config.relay_args for placeholder in ("{certificate}", "{key}"))


def generate_certificate(output: pathlib.Path) -> None:
    """Write a self-signed certificate and key into `output`.

    It matches what `openssl req -x509 -newkey rsa:2048 -nodes` writes: a
    self-signed RSA certificate for localhost valid for one day, with an
    unencrypted PKCS#8 key. The peers do not verify it, so it only has to be a
    certificate every relay accepts.
    """

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    public_key = key.public_key()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
        .sign(key, hashes.SHA256())
    )
    (output / KEY).write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (output / CERTIFICATE).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
