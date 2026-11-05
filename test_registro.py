"""Prueba todos los mecanismos del registro: operación correcta + cada acción de Eve."""
from mecanismos.registro import REGISTRO, ejecutar_alice, entregar, params_por_defecto

MSG = "Hola Bob, nos vemos a las 5"
fallos = 0
print(f"{'MECANISMO':38} {'ACCIÓN':58} {'BOB ACEPTA':10} ESPERADO")
for nombre, m in REGISTRO.items():
    variantes_params = [{}]
    if "autenticar_llave" in m["opciones"]:
        variantes_params = [{"autenticar_llave": True}, {"autenticar_llave": False}]
    for extra in variantes_params:
        res, ctx = ejecutar_alice(nombre, MSG, extra)
        pub = res["componentes_publicos"]
        assert not set(pub) & set(res["componentes_secretos"]), f"{nombre}: un secreto está en lo público"
        r = entregar(nombre, pub, ctx)
        ok = r["aceptado"] and (r.get("texto") in (MSG, None)) and r.get("detalle", {}).get("claves_coinciden", True)
        etq = nombre + (f" [{'pin' if extra['autenticar_llave'] else 'sin pin'}]" if extra else "")
        print(f"{etq:38} {'(sin ataque)':58} {str(r['aceptado']):10} True {'' if ok else '<-- FALLO'}")
        fallos += not ok
        for a in m["ataques"]:
            r = entregar(nombre, pub, ctx, a)
            esp = a["espera_aceptado"](ctx["params"]) if callable(a["espera_aceptado"]) else a["espera_aceptado"]
            bien = (r["aceptado"] == esp) and (a["verifica"](r) if a["verifica"] else True)
            print(f"{etq:38} {a['nombre'][:57]:58} {str(r['aceptado']):10} {esp} {'' if bien else '<-- FALLO'}")
            fallos += not bien

print("\n--- Ataques pasivos de laboratorio ---")
for nombre in ("Hash SHA-256 / SHA3-256", "KDF: Scrypt / PBKDF2"):
    m = REGISTRO[nombre]
    res, ctx = ejecutar_alice(nombre, "sunshine")
    titulo, fn = m["pasivo"]
    r = fn(res["componentes_publicos"], ctx["params"])
    print(nombre, "->", titulo, r)
    assert r["encontrada"] and r["contrasena"] == "sunshine"
print("\nFALLOS:", fallos)
assert fallos == 0
print("OK")
