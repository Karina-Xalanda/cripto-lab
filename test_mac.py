from mecanismos.mac import calcular_hmac, verificar_hmac, calcular_cmac, verificar_cmac
from ataques.mac_y_repeticion import (modificar_mensaje_con_mac,
                                      repeticion_sin_proteccion, repeticion_con_contador)

MSG = "Hola Bob, nos vemos a las 5"
print("=== OPERACIONES CORRECTAS ===")
for calc, ver in ((calcular_hmac, verificar_hmac), (calcular_cmac, verificar_cmac)):
    c = calc(MSG)
    r = ver(MSG, c["salida"], c["componentes_secretos"]["llave"])
    assert r["aceptado"]
    print(c["mecanismo"], "| etiqueta:", c["salida"][:20], "... |", r["explicacion"], c["metricas"])

print("\n=== EVE MODIFICA EL MENSAJE (sin la llave) ===")
res = modificar_mensaje_con_mac()
for nombre, d in res.items():
    print(f"{nombre}: mensaje original válido={d['original_valido']} | mensaje alterado válido={d['alterado_valido']}")
    assert d["original_valido"] and not d["alterado_valido"]

print("\n=== REPETICIÓN: Bob solo verifica HMAC ===")
for i, (ok, txt) in enumerate(repeticion_sin_proteccion()):
    print(f"Envío {i+1} ({'original' if i == 0 else 'reenviado por Eve'}): aceptado={ok} - {txt}")
    assert ok

print("\n=== REPETICIÓN: Bob verifica HMAC + contador ===")
res = repeticion_con_contador()
for i, (ok, txt) in enumerate(res):
    print(f"Envío {i+1} ({'original' if i == 0 else 'reenviado por Eve'}): aceptado={ok} - {txt}")
assert res[0][0] and not res[1][0] and not res[2][0]
print("\nOK")