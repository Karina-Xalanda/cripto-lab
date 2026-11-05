"""Escenario: derivación de contraseñas. Compara intentos/segundo de Eve
contra SHA-256 directo y contra Scrypt."""
import hashlib
import time
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SAL = b"sal-de-practica-16"


def intentos_por_segundo_sha256(segundos=1.0) -> dict:
    n, fin = 0, time.perf_counter() + segundos
    while time.perf_counter() < fin:
        hashlib.sha256(f"palabra{n}".encode()).digest()
        n += 1
    return {"metodo": "SHA-256 directo", "intentos": n, "intentos_por_seg": round(n / segundos)}


def intentos_por_segundo_scrypt(segundos=2.0, n_cost=2**14, r=8, p=1) -> dict:
    n, inicio = 0, time.perf_counter()
    while time.perf_counter() - inicio < segundos:
        Scrypt(salt=SAL, length=32, n=n_cost, r=r, p=p).derive(f"palabra{n}".encode())
        n += 1
    t = time.perf_counter() - inicio
    return {"metodo": f"Scrypt (n=2^{n_cost.bit_length()-1}, r={r}, p={p})",
            "intentos": n, "intentos_por_seg": round(n / t, 1)}