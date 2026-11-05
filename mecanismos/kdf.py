"""Derivación de claves (KDF): PBKDF2, Scrypt y HKDF."""
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from metricas import medir

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1   # costo: ~16 MiB de RAM por intento
PBKDF2_ITER = 600_000


def derivar_scrypt(contrasena: str, sal: bytes = None, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P) -> dict:
    sal = sal or os.urandom(16)
    datos = contrasena.encode("utf-8")

    def _derivar():
        return Scrypt(salt=sal, length=32, n=n, r=r, p=p).derive(datos)

    clave, metricas = medir(_derivar)
    metricas.update(bytes_entrada=len(datos), bytes_salida=len(clave),
                    memoria_teorica_kb=128 * n * r // 1024)
    return {
        "mecanismo": "KDF Scrypt",
        "entradas": {"contraseña": contrasena},
        "componentes_publicos": {"sal": sal.hex(), "n": n, "r": r, "p": p},
        "componentes_secretos": {"contraseña": contrasena},
        "salida": clave.hex(),
        "propiedad": "Derivación de claves / almacenamiento resistente de contraseñas",
        "metricas": metricas,
        "condiciones": "Sal aleatoria única (>=16 bytes) por usuario; n alto (>=2^14).",
    }


def derivar_pbkdf2(contrasena: str, sal: bytes = None, iteraciones=PBKDF2_ITER) -> dict:
    sal = sal or os.urandom(16)
    datos = contrasena.encode("utf-8")

    def _derivar():
        return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal,
                          iterations=iteraciones).derive(datos)

    clave, metricas = medir(_derivar)
    metricas.update(bytes_entrada=len(datos), bytes_salida=len(clave))
    return {
        "mecanismo": "KDF PBKDF2-HMAC-SHA256",
        "entradas": {"contraseña": contrasena},
        "componentes_publicos": {"sal": sal.hex(), "iteraciones": iteraciones},
        "componentes_secretos": {"contraseña": contrasena},
        "salida": clave.hex(),
        "propiedad": "Derivación de claves",
        "metricas": metricas,
        "condiciones": "Sal aleatoria; iteraciones altas (>=600,000 para SHA-256).",
    }


def derivar_hkdf(secreto_compartido: bytes, info: bytes = b"cripto-lab", sal: bytes = None) -> dict:
    """HKDF NO es para contraseñas: convierte un secreto YA fuerte
    (p. ej. el resultado de Diffie-Hellman) en llaves utilizables."""
    sal = sal or os.urandom(16)
    clave, metricas = medir(lambda: HKDF(algorithm=hashes.SHA256(), length=32,
                                         salt=sal, info=info).derive(secreto_compartido))
    metricas.update(bytes_entrada=len(secreto_compartido), bytes_salida=len(clave))
    return {
        "mecanismo": "KDF HKDF-SHA256",
        "entradas": {"secreto_compartido": secreto_compartido.hex()},
        "componentes_publicos": {"sal": sal.hex(), "info": info.decode()},
        "componentes_secretos": {"secreto_compartido": secreto_compartido.hex()},
        "salida": clave.hex(),
        "propiedad": "Derivación de claves a partir de un secreto fuerte",
        "metricas": metricas,
        "condiciones": "Entrada con alta entropía; NO usar con contraseñas humanas.",
    }