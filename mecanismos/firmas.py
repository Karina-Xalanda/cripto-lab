"""Firmas digitales: Ed25519 y RSA-PSS."""
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.exceptions import InvalidSignature
from metricas import medir

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def _pem_pub(k):
    return k.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _pem_priv(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()


def firmar(mensaje: str, algoritmo: str = "Ed25519") -> dict:
    datos = mensaje.encode()
    t0 = time.perf_counter()
    if algoritmo == "Ed25519":
        llave = ed25519.Ed25519PrivateKey.generate()
        firmar_fn = lambda: llave.sign(datos)
    else:
        llave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        firmar_fn = lambda: llave.sign(datos, PSS, hashes.SHA256())
    t_gen = (time.perf_counter() - t0) * 1000
    firma, metricas = medir(firmar_fn)
    metricas.update(bytes_entrada=len(datos), bytes_salida=len(firma),
                    tiempo_generacion_llaves_ms=round(t_gen, 2))
    return {
        "mecanismo": f"Firma digital {algoritmo}",
        "entradas": {"mensaje": mensaje},
        "componentes_publicos": {"mensaje": mensaje, "firma": firma.hex(), "llave_publica": _pem_pub(llave)},
        "componentes_secretos": {"llave_privada": _pem_priv(llave)},
        "salida": firma.hex(),
        "propiedad": "Integridad + autenticación + no repudio",
        "metricas": metricas,
        "condiciones": "Llave privada jamás se comparte; la llave pública debe estar autenticada (PKI); "
                       "RSA con PSS y >=2048 bits.",
    }


def verificar_firma(mensaje: str, firma_hex: str, llave_publica_pem: str, algoritmo: str = "Ed25519") -> dict:
    pub = serialization.load_pem_public_key(llave_publica_pem.encode())
    try:
        if algoritmo == "Ed25519":
            pub.verify(bytes.fromhex(firma_hex), mensaje.encode())
        else:
            pub.verify(bytes.fromhex(firma_hex), mensaje.encode(), PSS, hashes.SHA256())
        return {"aceptado": True, "explicacion": "Firma válida: el mensaje no cambió y lo firmó el dueño de la llave privada."}
    except InvalidSignature:
        return {"aceptado": False, "explicacion": "RECHAZADO: la firma no coincide con el mensaje (InvalidSignature)."}