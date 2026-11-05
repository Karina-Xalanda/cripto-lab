from mecanismos.hashes import calcular_huella, verificar_huella

r = calcular_huella("Hola Bob")
print(r["salida"]); print(r["metricas"])
assert verificar_huella("Hola Bob", r["salida"])
assert not verificar_huella("Hola Bob.", r["salida"])   # cambiar 1 carácter
print("OK: hash correcto y modificación detectada")