"""Cifrado de flujo: ChaCha20 y AES-CTR (ambos SIN autenticación)."""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from metricas import medir


def _flujo(nombre, algoritmo_fn, modo_fn, mensaje, llave):
    llave = llave or os.urandom(32)
    nonce = os.urandom(16)

    def _cifrar():
        enc = Cipher(algoritmo_fn(llave, nonce), modo_fn(nonce)).encryptor()
        return enc.update(mensaje.encode()) + enc.finalize()

    ct, metricas = medir(_cifrar)
    metricas.update(bytes_entrada=len(mensaje.encode()), bytes_salida=len(ct))
    return {
        "mecanismo": f"{nombre} (sin autenticación)",
        "entradas": {"mensaje": mensaje},
        "componentes_publicos": {"nonce": nonce.hex(), "texto_cifrado": ct.hex()},
        "componentes_secretos": {"llave": llave.hex()},
        "salida": ct.hex(),
        "propiedad": "Confidencialidad (NO integridad, NO autenticación)",
        "metricas": metricas,
        "condiciones": "NUNCA reutilizar (llave, nonce); añadir MAC; texto cifrado = mismo largo que el mensaje.",
    }


def cifrar_chacha20(mensaje, llave=None):
    return _flujo("ChaCha20", lambda k, n: algorithms.ChaCha20(k, n), lambda n: None, mensaje, llave)


def cifrar_aes_ctr(mensaje, llave=None):
    return _flujo("AES-256-CTR", lambda k, n: algorithms.AES(k), lambda n: modes.CTR(n), mensaje, llave)


def descifrar_flujo(nombre, texto_cifrado_hex, nonce_hex, llave_hex) -> dict:
    llave, nonce = bytes.fromhex(llave_hex), bytes.fromhex(nonce_hex)
    if nombre == "ChaCha20":
        c = Cipher(algorithms.ChaCha20(llave, nonce), mode=None)
    else:
        c = Cipher(algorithms.AES(llave), modes.CTR(nonce))
    d = c.decryptor()
    texto = (d.update(bytes.fromhex(texto_cifrado_hex)) + d.finalize()).decode("utf-8", errors="replace")
    return {"aceptado": True, "texto": texto,
            "explicacion": "Bob descifró sin error. Un cifrado de flujo no detecta modificaciones."}