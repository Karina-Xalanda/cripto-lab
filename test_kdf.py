from mecanismos.kdf import derivar_scrypt, derivar_pbkdf2, derivar_hkdf
from ataques.comparar_kdf import (intentos_por_segundo_sha256,
                                  intentos_por_segundo_scrypt)

for f in (derivar_scrypt, derivar_pbkdf2):
    r = f("sunshine")
    print(r["mecanismo"], "| salida:", r["salida"][:24], "...", r["metricas"])
r = derivar_hkdf(b"secreto-fuerte-de-prueba")
print(r["mecanismo"], "|", r["salida"][:24], "...", r["metricas"])

# Misma contraseña + misma sal -> misma llave (así Bob la verifica)
sal = bytes.fromhex(derivar_scrypt("abc")["componentes_publicos"]["sal"])
a = derivar_scrypt("abc", sal)["salida"]; b = derivar_scrypt("abc", sal)["salida"]
assert a == b
# Misma contraseña + sal distinta -> llave distinta
assert derivar_scrypt("abc")["salida"] != derivar_scrypt("abc")["salida"]
print("OK: la sal cambia el resultado")

print("\nEve intentando adivinar durante unos segundos...")
s = intentos_por_segundo_sha256(); k = intentos_por_segundo_scrypt()
print(s); print(k)
print(f"SHA-256 es ~{s['intentos_por_seg']/k['intentos_por_seg']:,.0f} veces más rápido de atacar")