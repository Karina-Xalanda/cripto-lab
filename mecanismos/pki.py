"""Infraestructura de clave pública (PKI): CA, certificados X.509 y verificación."""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.exceptions import InvalidSignature


def _nombre(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def crear_ca(nombre: str):
    """Crea una CA raíz autofirmada. Devuelve (llave_privada, certificado)."""
    llave = ec.generate_private_key(ec.SECP256R1())
    ahora = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_nombre(nombre)).issuer_name(_nombre(nombre))
            .public_key(llave.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(ahora - datetime.timedelta(minutes=1))
            .not_valid_after(ahora + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(llave, hashes.SHA256()))
    return llave, cert


def emitir_certificado(ca_llave, ca_cert, nombre_sujeto: str, llave_publica, dias: int = 365):
    ahora = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(_nombre(nombre_sujeto)).issuer_name(ca_cert.subject)
            .public_key(llave_publica).serial_number(x509.random_serial_number())
            .not_valid_before(ahora - datetime.timedelta(minutes=1))
            .not_valid_after(ahora + datetime.timedelta(days=dias))
            .sign(ca_llave, hashes.SHA256()))


def verificar_certificado(cert, almacen_confianza: list, nombre_esperado: str) -> dict:
    """Bob solo confía en las CAs de su almacén de confianza."""
    ahora = datetime.datetime.now(datetime.timezone.utc)
    if not (cert.not_valid_before_utc <= ahora <= cert.not_valid_after_utc):
        return {"aceptado": False, "explicacion": "RECHAZADO: certificado fuera de su periodo de validez."}
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != nombre_esperado:
        return {"aceptado": False, "explicacion": f"RECHAZADO: el certificado es de '{cn}', no de '{nombre_esperado}'."}
    for ca in almacen_confianza:
        try:
            cert.verify_directly_issued_by(ca)
            return {"aceptado": True, "explicacion": "Certificado aceptado: firmado por una CA de confianza."}
        except (InvalidSignature, ValueError, TypeError):
            continue
    return {"aceptado": False, "explicacion": "RECHAZADO: el emisor no es una CA de confianza (firma no verificable)."}


def cert_pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()