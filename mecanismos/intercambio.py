"""Intercambio de claves: X25519 (Diffie-Hellman de curva elíptica) + HKDF."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from metricas import medir


def pub_bytes(priv) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derivar_clave(secreto: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cripto-lab-x25519").derive(secreto)


def acuerdo_x25519() -> dict:
    def _acuerdo():
        a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        sa = a.exchange(x25519.X25519PublicKey.from_public_bytes(pub_bytes(b)))
        sb = b.exchange(x25519.X25519PublicKey.from_public_bytes(pub_bytes(a)))
        return a, b, sa, sb

    (a, b, sa, sb), metricas = medir(_acuerdo)
    ka, kb = derivar_clave(sa), derivar_clave(sb)
    metricas.update(bytes_entrada=32, bytes_salida=len(ka))
    return {
        "mecanismo": "Acuerdo de claves X25519 (sin autenticar)",
        "entradas": {"llave_privada_alice": "(secreta)", "llave_privada_bob": "(secreta)"},
        "componentes_publicos": {"publica_alice": pub_bytes(a).hex(), "publica_bob": pub_bytes(b).hex()},
        "componentes_secretos": {"privada_alice": a.private_bytes_raw().hex(),
                                 "privada_bob": b.private_bytes_raw().hex(), "secreto_compartido": sa.hex()},
        "salida": ka.hex(),
        "claves_coinciden": ka == kb,
        "propiedad": "Establecimiento de claves (NO autentica a los participantes)",
        "metricas": metricas,
        "condiciones": "Llaves efímeras nuevas por sesión; derivar con HKDF; AUTENTICAR los valores públicos "
                       "(firmas o certificados) para evitar man-in-the-middle.",
    }