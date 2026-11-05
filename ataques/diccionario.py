"""Escenario: contraseña débil + ataque de diccionario contra un hash SHA-256.

DATOS DE PRÁCTICA: la contraseña y el diccionario son inventados para la tarea.
"""
import hashlib
import time

DICCIONARIO = [
    "123456", "password", "qwerty", "abc123", "111111", "iloveyou",
    "admin", "welcome", "monkey", "dragon", "football", "letmein",
    "sunshine", "princesa", "contraseña", "hola123", "mexico", "veracruz",
    "ciber2026", "master", "shadow", "superman", "batman", "michael",
]

CONTRASENA_DEBIL = "sunshine"          # contraseña de prueba (débil)
CONTRASENA_FUERTE = "Xq7#vL9!mT2@pR4z"  # contraseña de prueba (fuerte)


def sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def ataque_diccionario(hash_objetivo: str, diccionario=DICCIONARIO) -> dict:
    """Eve calcula el hash de cada palabra y lo compara con el hash robado.

    OJO: Eve NO 'descifra' el hash (no se puede invertir). Solo ADIVINA
    la contraseña probando candidatos hasta que uno produce el mismo hash.
    """
    inicio = time.perf_counter()
    intentos = 0
    for palabra in diccionario:
        intentos += 1
        if sha256_hex(palabra) == hash_objetivo:
            return {"encontrada": True, "contrasena": palabra, "intentos": intentos,
                    "tiempo_ms": round((time.perf_counter() - inicio) * 1000, 4)}
    return {"encontrada": False, "contrasena": None, "intentos": intentos,
            "tiempo_ms": round((time.perf_counter() - inicio) * 1000, 4)}