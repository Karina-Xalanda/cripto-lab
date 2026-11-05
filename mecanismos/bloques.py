"""Cifrado simétrico por bloques: AES-CBC (sin autenticación) y AES-GCM (autenticado)."""
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from metricas import medir


def cifrar_cbc(mensaje: str, llave: bytes = None) -> dict:
    llave = llave or os.urandom(32)          # AES-256
    iv = os.urandom(16)                      # IV aleatorio e impredecible

    def _cifrar():
        padder = padding.PKCS7(128).padder()
        datos = padder.update(mensaje.encode()) + padder.finalize()
        enc = Cipher(algorithms.AES(llave), modes.CBC(iv)).encryptor()
        return enc.update(datos) + enc.finalize()

    ct, metricas = medir(_cifrar)
    metricas.update(bytes_entrada=len(mensaje.encode()), bytes_salida=len(ct))
    return {
        "mecanismo": "AES-256-CBC (sin autenticación)",
        "entradas": {"mensaje": mensaje},
        "componentes_publicos": {"iv": iv.hex(), "texto_cifrado": ct.hex()},
        "componentes_secretos": {"llave": llave.hex()},
        "salida": ct.hex(),
        "propiedad": "Confidencialidad (NO integridad, NO autenticación)",
        "metricas": metricas,
        "condiciones": "IV aleatorio nuevo en cada mensaje; llave de 256 bits; añadir MAC.",
    }


def descifrar_cbc(texto_cifrado_hex: str, iv_hex: str, llave_hex: str) -> dict:
    try:
        dec = Cipher(algorithms.AES(bytes.fromhex(llave_hex)),
                     modes.CBC(bytes.fromhex(iv_hex))).decryptor()
        datos = dec.update(bytes.fromhex(texto_cifrado_hex)) + dec.finalize()
        un = padding.PKCS7(128).unpadder()
        texto = (un.update(datos) + un.finalize()).decode("utf-8", errors="replace")
        return {"aceptado": True, "texto": texto,
                "explicacion": "Bob descifró sin error. CBC no verifica si el mensaje fue alterado."}
    except ValueError as e:
        return {"aceptado": False, "texto": None,
                "explicacion": f"Error de relleno ({e}). Fue casualidad, no una verificación de integridad."}


def cifrar_gcm(mensaje: str, aad: str = "", llave: bytes = None) -> dict:
    llave = llave or AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)                   # 96 bits, NUNCA repetir con la misma llave
    aad_b = aad.encode()

    salida, metricas = medir(lambda: AESGCM(llave).encrypt(nonce, mensaje.encode(), aad_b))
    ct, tag = salida[:-16], salida[-16:]
    metricas.update(bytes_entrada=len(mensaje.encode()), bytes_salida=len(salida))
    return {
        "mecanismo": "AES-256-GCM (autenticado, AEAD)",
        "entradas": {"mensaje": mensaje, "datos_asociados": aad},
        "componentes_publicos": {"nonce": nonce.hex(), "texto_cifrado": ct.hex(),
                                 "etiqueta": tag.hex(), "datos_asociados": aad},
        "componentes_secretos": {"llave": llave.hex()},
        "salida": salida.hex(),
        "propiedad": "Confidencialidad + integridad + autenticación",
        "metricas": metricas,
        "condiciones": "Nonce único por llave (repetirlo rompe GCM); llave de 128/256 bits.",
    }


def descifrar_gcm(nonce_hex, texto_cifrado_hex, etiqueta_hex, aad, llave_hex) -> dict:
    try:
        texto = AESGCM(bytes.fromhex(llave_hex)).decrypt(
            bytes.fromhex(nonce_hex),
            bytes.fromhex(texto_cifrado_hex) + bytes.fromhex(etiqueta_hex),
            aad.encode())
        return {"aceptado": True, "texto": texto.decode(),
                "explicacion": "Etiqueta válida: texto y datos asociados no fueron modificados."}
    except InvalidTag:
        return {"aceptado": False, "texto": None,
                "explicacion": "RECHAZADO: la etiqueta no coincide (InvalidTag). Hubo modificación."}