# SPDX-License-Identifier: MIT
"""The TLS identity Veer presents: a self-signed certificate, which is all a
peer visible to everyone asks for. Neither side checks the other's."""
import datetime
import logging
import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import config

log = logging.getLogger('veer.identity')

CERTIFICATE = 'certificate.pem'
KEY = 'key.pem'
VALID_DAYS = 5 * 365
# Renewed this long before it runs out, so a running receiver never shows an
# expired one.
RENEW_DAYS = 30


def _still_valid(certificate_path):
    try:
        with open(certificate_path, 'rb') as f:
            certificate = x509.load_pem_x509_certificate(f.read())
    except (OSError, ValueError):
        return False
    expires = certificate.not_valid_after_utc
    return expires - datetime.datetime.now(datetime.timezone.utc) > datetime.timedelta(days=RENEW_DAYS)


def _write_private(path, data):
    """Write a file only this user can read, as far as the platform allows.
    On Windows the per-user data folder already is."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)


def create(certificate_path, key_path, common_name=config.CERTIFICATE_NAME):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write_private(key_path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    with open(certificate_path, 'wb') as out:
        out.write(certificate.public_bytes(serialization.Encoding.PEM))


def ensure(keys_dir=None):
    """The certificate and key paths, creating the pair on first use or
    when the certificate is close to expiring."""
    keys_dir = keys_dir or config.keys_dir()
    certificate = os.path.join(keys_dir, CERTIFICATE)
    key = os.path.join(keys_dir, KEY)
    if os.path.isfile(key) and _still_valid(certificate):
        return certificate, key
    os.makedirs(keys_dir, exist_ok=True)
    log.info('creating a self-signed certificate in %s', keys_dir)
    create(certificate, key)
    return certificate, key


def server_context(keys_dir=None):
    certificate, key = ensure(keys_dir)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    # Senders present self-signed certificates, so none is asked for.
    context.verify_mode = ssl.CERT_NONE
    return context


def client_context(keys_dir=None):
    certificate, key = ensure(keys_dir)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # A receiver visible to everyone presents a certificate nothing vouches
    # for, and takes ours the same way.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certificate, key)
    return context
