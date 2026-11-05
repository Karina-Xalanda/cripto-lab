"""Códigos de autenticación de mensajes (MAC): HMAC-SHA256 y CMAC-AES."""
import os
from cryptography.hazmat.primitives import hashes, hmac, cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.exceptions import InvalidSignature
from metricas import medir


def _resultado(nombre, mensaje, llave, etiqueta, metricas, condiciones):
    metricas.update(bytes_entrada=len(mensaje.encode()), bytes_salida=len(etiqueta))
    return {
        "mecanismo": nombre,
        "entradas": {"mensaje": mensaje},
        "componentes_publicos": {"mensaje": mensaje, "etiqueta": etiqueta.hex()},
        "componentes_secretos": {"llave": llave.hex()},
        "salida": etiqueta.hex(),
        "propiedad": "Integridad + autenticación (NO confidencialidad: el mensaje va en claro)",
        "metricas": metricas,
        "condiciones": condiciones,
    }


def calcular_hmac(mensaje: str, llave: bytes = None) -> dict:
    llave = llave or os.urandom(32)

    def _mac():
        h = hmac.HMAC(llave, hashes.SHA256())
        h.update(mensaje.encode())
        return h.finalize()

    etiqueta, m = medir(_mac)
    return _resultado("HMAC-SHA256", mensaje, llave, etiqueta, m,
                      "Llave secreta compartida de >=32 bytes; comparar etiquetas en tiempo constante; "
                      "no protege contra repetición por sí solo.")


def calcular_cmac(mensaje: str, llave: bytes = None) -> dict:
    llave = llave or os.urandom(16)

    def _mac():
        c = cmac.CMAC(algorithms.AES(llave))
        c.update(mensaje.encode())
        return c.finalize()

    etiqueta, m = medir(_mac)
    return _resultado("CMAC-AES-128", mensaje, llave, etiqueta, m,
                      "Llave AES secreta (usar solo para CMAC); no protege contra repetición por sí solo.")


def _verificar(obj, mensaje, etiqueta_hex):
    try:
        obj.update(mensaje.encode())
        obj.verify(bytes.fromhex(etiqueta_hex))      # comparación en tiempo constante
        return {"aceptado": True, "explicacion": "Etiqueta válida: mensaje íntegro y enviado por quien tiene la llave."}
    except InvalidSignature:
        return {"aceptado": False, "explicacion": "RECHAZADO: la etiqueta no corresponde al mensaje recibido."}


def verificar_hmac(mensaje: str, etiqueta_hex: str, llave_hex: str) -> dict:
    return _verificar(hmac.HMAC(bytes.fromhex(llave_hex), hashes.SHA256()), mensaje, etiqueta_hex)


def verificar_cmac(mensaje: str, etiqueta_hex: str, llave_hex: str) -> dict:
    return _verificar(cmac.CMAC(algorithms.AES(bytes.fromhex(llave_hex))), mensaje, etiqueta_hex)