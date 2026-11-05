"""Cifrado de clave pública: RSA-OAEP."""
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from metricas import medir

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _pem_pub(k):
    return k.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _pem_priv(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()


def cifrar_rsa(mensaje: str, bits: int = 2048) -> dict:
    t0 = time.perf_counter()
    llave = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    t_gen = (time.perf_counter() - t0) * 1000
    datos = mensaje.encode()
    maximo = bits // 8 - 2 * 32 - 2          # límite de OAEP con SHA-256
    if len(datos) > maximo:
        raise ValueError(f"RSA-OAEP de {bits} bits solo cifra hasta {maximo} bytes (recibió {len(datos)}). "
                         "Para mensajes largos se cifra una llave AES con RSA (cifrado híbrido).")
    ct, metricas = medir(lambda: llave.public_key().encrypt(datos, OAEP))
    metricas.update(bytes_entrada=len(datos), bytes_salida=len(ct),
                    tiempo_generacion_llaves_ms=round(t_gen, 2))
    return {
        "mecanismo": f"RSA-{bits}-OAEP",
        "entradas": {"mensaje": mensaje},
        "componentes_publicos": {"llave_publica": _pem_pub(llave), "texto_cifrado": ct.hex()},
        "componentes_secretos": {"llave_privada": _pem_priv(llave)},
        "salida": ct.hex(),
        "propiedad": "Confidencialidad (solo el dueño de la llave privada descifra)",
        "metricas": metricas,
        "condiciones": f"Usar OAEP (nunca RSA 'de libro'); llave >=2048 bits; mensaje <= {maximo} bytes; "
                       "la llave pública debe estar autenticada (certificado).",
    }


def descifrar_rsa(texto_cifrado_hex: str, llave_privada_pem: str) -> dict:
    try:
        llave = serialization.load_pem_private_key(llave_privada_pem.encode(), password=None)
        texto = llave.decrypt(bytes.fromhex(texto_cifrado_hex), OAEP).decode()
        return {"aceptado": True, "texto": texto, "explicacion": "Descifrado con la llave privada de Bob."}
    except ValueError:
        return {"aceptado": False, "texto": None,
                "explicacion": "RECHAZADO: no se pudo descifrar (texto alterado o llave incorrecta)."}