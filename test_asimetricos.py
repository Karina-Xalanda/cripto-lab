from mecanismos.rsa_cifrado import cifrar_rsa, descifrar_rsa
from mecanismos.firmas import firmar, verificar_firma
from mecanismos.intercambio import acuerdo_x25519
from ataques.escenarios_asimetricos import (modificar_mensaje_firmado, mitm_sin_autenticacion,
                                            mitm_con_firmas, pki_ca_no_confiable)
MSG = "Hola Bob, nos vemos a las 5"

print("=== OPERACIONES CORRECTAS ===")
c = cifrar_rsa(MSG); r = descifrar_rsa(c["salida"], c["componentes_secretos"]["llave_privada"])
assert r["texto"] == MSG; print(c["mecanismo"], "->", r["texto"], c["metricas"])
try:
    cifrar_rsa("x" * 300)
except ValueError as e:
    print("Mal uso (mensaje largo):", e)
for alg in ("Ed25519", "RSA-PSS"):
    f = firmar(MSG, alg); p = f["componentes_publicos"]
    r = verificar_firma(MSG, p["firma"], p["llave_publica"], alg)
    assert r["aceptado"]; print(f["mecanismo"], "->", r["explicacion"], f["metricas"])
d = acuerdo_x25519(); assert d["claves_coinciden"]; print(d["mecanismo"], "-> claves coinciden:", d["claves_coinciden"], d["metricas"])

print("\n=== EVE MODIFICA UN MENSAJE FIRMADO ===")
for alg in ("Ed25519", "RSA-PSS"):
    r = modificar_mensaje_firmado(alg)
    print(alg, "| original:", r["original"]["aceptado"], "| alterado:", r["alterado"]["aceptado"], "-", r["alterado"]["explicacion"])
    assert r["original"]["aceptado"] and not r["alterado"]["aceptado"]

print("\n=== ACUERDO DE CLAVES SIN AUTENTICAR (MITM) ===")
r = mitm_sin_autenticacion(); print(r)
assert not r["alice_y_bob_comparten_clave"] and r["eve_tiene_clave_de_alice"] and r["eve_tiene_clave_de_bob"]
print("\n=== ACUERDO DE CLAVES CON FIRMAS ===")
r = mitm_con_firmas(); print(r); assert not r["aceptado"]

print("\n=== PKI ===")
r = pki_ca_no_confiable()
print("Certificado legítimo:", r["legitimo"]); print("Certificado de CA no confiable:", r["falso"])
assert r["legitimo"]["aceptado"] and not r["falso"]["aceptado"]
print("\nOK")