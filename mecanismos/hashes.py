"""Funciones hash criptográficas: SHA-256 y SHA3-256."""
import hashlib
from metricas import medir

ALGORITMOS = {"SHA-256": hashlib.sha256, "SHA3-256": hashlib.sha3_256}


def calcular_huella(mensaje: str, algoritmo: str = "SHA-256") -> dict:
    datos = mensaje.encode("utf-8")
    huella, metricas = medir(lambda: ALGORITMOS[algoritmo](datos).digest())
    metricas["bytes_entrada"] = len(datos)
    metricas["bytes_salida"] = len(huella)
    return {
        "mecanismo": f"Hash {algoritmo}",
        "entradas": {"mensaje": mensaje},
        "componentes_publicos": {"huella": huella.hex()},
        "componentes_secretos": {},          # un hash no usa llaves
        "salida": huella.hex(),
        "propiedad": "Integridad (solo si la huella llega por un canal confiable)",
        "metricas": metricas,
        "condiciones": ("No usar para guardar contraseñas sin sal ni KDF. "
                        "No autentica: cualquiera puede recalcularlo."),
    }


def verificar_huella(mensaje: str, huella_hex: str, algoritmo: str = "SHA-256") -> bool:
    return calcular_huella(mensaje, algoritmo)["salida"] == huella_hex