"""Construcción esponja y salida extensible (XOF): SHAKE128 y SHAKE256 (Keccak)."""
import hashlib
from metricas import medir

VARIANTES = {"SHAKE128": hashlib.shake_128, "SHAKE256": hashlib.shake_256}
# Parámetros de la esponja (estado de 1600 bits = tasa r + capacidad c)
PARAMETROS = {"SHAKE128": {"tasa_bits": 1344, "capacidad_bits": 256},
              "SHAKE256": {"tasa_bits": 1088, "capacidad_bits": 512}}


def calcular_shake(mensaje: str, variante: str = "SHAKE128", longitud: int = 32) -> dict:
    datos = mensaje.encode("utf-8")
    salida, metricas = medir(lambda: VARIANTES[variante](datos).digest(longitud))
    metricas.update(bytes_entrada=len(datos), bytes_salida=len(salida))
    return {
        "mecanismo": f"Esponja {variante} (XOF)",
        "entradas": {"mensaje": mensaje, "longitud_salida_bytes": longitud},
        "componentes_publicos": {"mensaje": mensaje, "salida": salida.hex(), "longitud_bytes": longitud},
        "componentes_secretos": {},
        "salida": salida.hex(),
        "propiedad": "Integridad (la salida puede tener la longitud que se pida; no usa llaves)",
        "metricas": metricas,
        "condiciones": ("Pedir salida >= 32 bytes (SHAKE128) o >= 64 bytes (SHAKE256) para conservar la "
                        "resistencia a colisiones; no autentica; no usar para contraseñas sin KDF. "
                        f"Esponja: {PARAMETROS[variante]}."),
    }


def verificar_shake(mensaje: str, salida_hex: str, variante: str = "SHAKE128") -> bool:
    longitud = len(bytes.fromhex(salida_hex))
    return calcular_shake(mensaje, variante, longitud)["salida"] == salida_hex
