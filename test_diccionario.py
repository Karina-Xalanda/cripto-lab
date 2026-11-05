from ataques.diccionario import (ataque_diccionario, sha256_hex,
                                 CONTRASENA_DEBIL, CONTRASENA_FUERTE)

for nombre, pwd in [("DÉBIL", CONTRASENA_DEBIL), ("FUERTE", CONTRASENA_FUERTE)]:
    h = sha256_hex(pwd)
    print(f"\n--- Contraseña {nombre} ---")
    print("Hash que ve Eve:", h)
    print("Resultado del ataque:", ataque_diccionario(h))