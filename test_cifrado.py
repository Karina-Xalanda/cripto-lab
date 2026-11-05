from mecanismos.bloques import cifrar_cbc, descifrar_cbc, cifrar_gcm, descifrar_gcm
from mecanismos.flujo import cifrar_chacha20, cifrar_aes_ctr, descifrar_flujo
from ataques.manipulacion import (alterar_sin_autenticacion, alterar_gcm_texto_cifrado,
                                  alterar_gcm_datos_asociados, reutilizacion_de_nonce)

MSG = "Hola Bob, nos vemos a las 5"
print("=== OPERACIONES CORRECTAS ===")
c = cifrar_cbc(MSG); p = c["componentes_publicos"]
r = descifrar_cbc(p["texto_cifrado"], p["iv"], c["componentes_secretos"]["llave"])
assert r["texto"] == MSG; print(c["mecanismo"], "->", r["texto"], c["metricas"])

c = cifrar_gcm(MSG, aad="id=42"); p = c["componentes_publicos"]
r = descifrar_gcm(p["nonce"], p["texto_cifrado"], p["etiqueta"], p["datos_asociados"], c["componentes_secretos"]["llave"])
assert r["texto"] == MSG; print(c["mecanismo"], "->", r["texto"], c["metricas"])

for f, nombre in ((cifrar_chacha20, "ChaCha20"), (cifrar_aes_ctr, "AES-CTR")):
    c = f(MSG); p = c["componentes_publicos"]
    r = descifrar_flujo(nombre, p["texto_cifrado"], p["nonce"], c["componentes_secretos"]["llave"])
    assert r["texto"] == MSG; print(c["mecanismo"], "->", r["texto"], c["metricas"])

print("\n=== EVE MODIFICA DATOS ===")
r = alterar_sin_autenticacion()
print("[AES-CTR sin autenticación] original:", r["original"], "| Bob recibe:", r["bob_recibe"], "| aceptado:", r["aceptado"])
assert r["bob_recibe"] == "Transferir $900 a Bob"
r = alterar_gcm_texto_cifrado(); print("[GCM texto cifrado alterado]", r["aceptado"], "-", r["explicacion"]); assert not r["aceptado"]
r = alterar_gcm_datos_asociados(); print("[GCM datos asociados alterados]", r["aceptado"], "-", r["explicacion"]); assert not r["aceptado"]

print("\n=== MAL USO: reutilizar nonce ===")
r = reutilizacion_de_nonce(); print("XOR(cifrados) == XOR(textos):", r["iguales"]); assert r["iguales"]
print("\nOK")