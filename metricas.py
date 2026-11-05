"""Medición de tiempo y memoria de una operación criptográfica."""
import time
import tracemalloc


def medir(funcion, *args, **kwargs):
    """Ejecuta funcion(*args) y devuelve (resultado, metricas).

    LIMITACIÓN: tracemalloc solo ve la memoria que reserva Python.
    Las bibliotecas nativas en C (como OpenSSL, que usa `cryptography`)
    reservan memoria propia que NO aparece aquí.
    """
    tracemalloc.start()
    inicio = time.perf_counter()
    resultado = funcion(*args, **kwargs)
    tiempo_ms = (time.perf_counter() - inicio) * 1000
    _, pico = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return resultado, {"tiempo_ms": round(tiempo_ms, 4),
                       "memoria_kb": round(pico / 1024, 2)}