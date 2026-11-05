"""Registro de mecanismos: conecta cada mecanismo con los paneles Alice, Bob y Eve.

Para cada mecanismo define:
  alice(mensaje, params) -> (resultado, ctx_bob)   ctx_bob = lo que Bob tiene de antemano (llaves, CA...)
  bob(pub, ctx)          -> {"aceptado", "texto", "explicacion", ...}
  ataques                -> acciones de Eve: fn(pub, params) -> (pub_modificado, meta)
Eve SOLO recibe `componentes_publicos`; nunca `componentes_secretos` ni `ctx_bob`.
"""
import os
import time
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.exceptions import InvalidSignature

from metricas import medir
from ataques.diccionario import DICCIONARIO
from mecanismos.hashes import calcular_huella, verificar_huella, ALGORITMOS
from mecanismos.esponja import calcular_shake, verificar_shake
from mecanismos.bloques import cifrar_cbc, descifrar_cbc, cifrar_gcm, descifrar_gcm
from mecanismos.flujo import cifrar_chacha20, cifrar_aes_ctr, descifrar_flujo
from mecanismos.mac import calcular_hmac, verificar_hmac, calcular_cmac, verificar_cmac
from mecanismos.kdf import derivar_scrypt, derivar_pbkdf2
from mecanismos.rsa_cifrado import cifrar_rsa, descifrar_rsa
from mecanismos.firmas import firmar, verificar_firma
from mecanismos.intercambio import pub_bytes, derivar_clave
from mecanismos.pki import crear_ca, emitir_certificado, verificar_certificado, cert_pem

REGISTRO = {}


# ----------------------------------------------------------------- utilidades
def _res(ok, texto, expl, **extra):
    return {"aceptado": ok, "texto": texto, "explicacion": expl, **extra}


def _xor_hex(h, pos=0, delta=1):
    b = bytearray(bytes.fromhex(h))
    b[pos] ^= delta
    return b.hex()


def _atk(nombre, fn, espera_aceptado, descripcion, verifica=None):
    return {"nombre": nombre, "fn": fn, "espera_aceptado": espera_aceptado,
            "descripcion": descripcion, "verifica": verifica}


def _reg(nombre, categoria, apartado, alice, bob, ataques, eve_obtiene, info,
         opciones=None, pasivo=None, post=None):
    REGISTRO[nombre] = dict(nombre=nombre, categoria=categoria, apartado=apartado, alice=alice, bob=bob,
                            ataques=ataques, eve_obtiene=eve_obtiene, info=info,
                            opciones=opciones or {}, pasivo=pasivo, post=post)


def params_por_defecto(nombre):
    return {k: v["defecto"] for k, v in REGISTRO[nombre]["opciones"].items()}


def ejecutar_alice(nombre, mensaje, params=None):
    params = {**params_por_defecto(nombre), **(params or {})}
    resultado, ctx = REGISTRO[nombre]["alice"](mensaje, params)
    ctx = {**ctx, "params": params}
    return resultado, ctx


def entregar(nombre, pub, ctx, ataque=None):
    """Eve decide qué entregar a Bob (ataque=None: lo deja pasar tal cual). Bob verifica."""
    m = REGISTRO[nombre]
    pub2, meta = (pub, {}) if ataque is None else ataque["fn"](pub, ctx["params"])
    try:
        res = m["bob"](pub2, ctx)
    except (ValueError, KeyError, InvalidSignature) as e:
        res = _res(False, None, f"RECHAZADO: el paquete no se pudo procesar ({type(e).__name__}).")
    if m["post"]:
        res = m["post"](res, pub2, meta, ctx)
    res["pub_entregado"] = pub2
    return res


def _dicc(prueba):
    ini, n = time.perf_counter(), 0
    for w in DICCIONARIO:
        n += 1
        if prueba(w):
            return {"encontrada": True, "contrasena": w, "intentos": n,
                    "tiempo_ms": round((time.perf_counter() - ini) * 1000, 2)}
    return {"encontrada": False, "contrasena": None, "intentos": n,
            "tiempo_ms": round((time.perf_counter() - ini) * 1000, 2)}


def _I(entradas, componentes, secreto, publico, salidas, mal_uso):
    return dict(entradas=entradas, componentes=componentes, secreto=secreto,
                publico=publico, salidas=salidas, mal_uso=mal_uso)


# ------------------------------------------------------------------- HASH
def _alice_hash(msg, p):
    r = calcular_huella(msg, p["algoritmo"])
    r["componentes_publicos"] = {"mensaje": msg, "huella": r["salida"]}
    return r, {}


def _bob_hash(pub, ctx):
    ok = verificar_huella(pub["mensaje"], pub["huella"], ctx["params"]["algoritmo"])
    return _res(ok, pub["mensaje"] if ok else None,
                "La huella coincide con el mensaje (pero no prueba QUIÉN la envió)." if ok
                else "RECHAZADO: la huella no coincide con el mensaje recibido.")


def _a_hash_mod(pub, p):
    return {**pub, "mensaje": pub["mensaje"] + "!"}, {}


def _a_hash_recalc(pub, p):
    m = pub["mensaje"] + "!"
    return {"mensaje": m, "huella": calcular_huella(m, p["algoritmo"])["salida"]}, {}


_reg("Hash SHA-256 / SHA3-256", "Cifrados sin uso de llaves", "Funciones hash criptográficas",
     _alice_hash, _bob_hash,
     [_atk("Modificar el mensaje (dejar la huella)", _a_hash_mod, False,
           "Eve cambia el mensaje pero no la huella: Bob lo detecta."),
      _atk("Modificar el mensaje Y recalcular la huella", _a_hash_recalc, True,
           "Eve recalcula la huella: Bob acepta. Un hash sin llave NO autentica.")],
     lambda pub: [f"Ve el mensaje completo y la huella ({len(pub['huella'])//2} bytes).",
                  "Puede recalcular huellas de cualquier texto (no hay secreto).",
                  "No puede invertir la huella, pero sí probar adivinanzas (diccionario)."],
     _I("Mensaje", "Ninguno (no usa llaves)", "Nada", "Mensaje y huella", "Huella de tamaño fijo",
        "Guardar contraseñas con hash rápido y sin sal permite ataques de diccionario; "
        "el hash por sí solo no autentica al emisor."),
     opciones={"algoritmo": {"tipo": "seleccion", "valores": ["SHA-256", "SHA3-256"], "defecto": "SHA-256"}},
     pasivo=("Ataque de diccionario contra la huella",
             lambda pub, p: _dicc(lambda w: ALGORITMOS[p["algoritmo"]](w.encode()).hexdigest() == pub["huella"])))


# ----------------------------------------------------------------- ESPONJA
def _alice_shake(msg, p):
    return calcular_shake(msg, p["variante"], int(p["longitud"])), {}


def _bob_shake(pub, ctx):
    ok = verificar_shake(pub["mensaje"], pub["salida"], ctx["params"]["variante"])
    return _res(ok, pub["mensaje"] if ok else None,
                "La salida coincide con el mensaje (no prueba quién la envió)." if ok
                else "RECHAZADO: la salida no coincide con el mensaje recibido.")


def _a_shake_mod(pub, p):
    return {**pub, "mensaje": pub["mensaje"] + "!"}, {}


def _a_shake_recalc(pub, p):
    m = pub["mensaje"] + "!"
    r = calcular_shake(m, p["variante"], pub["longitud_bytes"])
    return {"mensaje": m, "salida": r["salida"], "longitud_bytes": pub["longitud_bytes"]}, {}


_reg("Esponja SHAKE128 / SHAKE256", "Cifrados sin uso de llaves", "Construcción esponja y salida extensible",
     _alice_shake, _bob_shake,
     [_atk("Modificar el mensaje (dejar la salida)", _a_shake_mod, False,
           "Bob recalcula la salida y no coincide."),
      _atk("Modificar el mensaje Y recalcular la salida", _a_shake_recalc, True,
           "Sin llave, Eve recalcula todo: tampoco autentica.")],
     lambda pub: [f"Ve el mensaje y la salida de {pub['longitud_bytes']} bytes.",
                  "Una salida más corta es prefijo de una más larga (propiedad XOF).",
                  "Puede recalcular la salida de cualquier mensaje."],
     _I("Mensaje, variante (SHAKE128/256), longitud de salida", "Ninguno; internamente tasa r y capacidad c",
        "Nada", "Mensaje y salida", "Salida de longitud elegida",
        "Pedir salidas demasiado cortas baja la resistencia a colisiones; no autentica."),
     opciones={"variante": {"tipo": "seleccion", "valores": ["SHAKE128", "SHAKE256"], "defecto": "SHAKE128"},
               "longitud": {"tipo": "numero", "min": 8, "max": 128, "defecto": 32}})


# ------------------------------------------------------------------- CBC
def _alice_cbc(msg, p):
    r = cifrar_cbc(msg)
    return r, {"llave": r["componentes_secretos"]["llave"]}


def _bob_cbc(pub, ctx):
    r = descifrar_cbc(pub["texto_cifrado"], pub["iv"], ctx["llave"])
    return _res(r["aceptado"], r["texto"], r["explicacion"])


_reg("AES-256-CBC (sin autenticación)", "Cifrado simétrico", "Cifrado simétrico por bloques",
     _alice_cbc, _bob_cbc,
     [_atk("Alterar un byte del texto cifrado", lambda pub, p: ({**pub, "texto_cifrado": _xor_hex(pub["texto_cifrado"], 0, 1)}, {}),
           True, "Bob descifra y obtiene un bloque corrupto sin ninguna alarma (con mensajes de 17+ bytes)."),
      _atk("Alterar el IV", lambda pub, p: ({**pub, "iv": _xor_hex(pub["iv"], 0, 1)}, {}),
           True, "Cambia de forma PREDECIBLE el primer bloque del texto claro; Bob no lo detecta.")],
     lambda pub: [f"Ve IV y texto cifrado de {len(pub['texto_cifrado'])//2} bytes (revela el tamaño del mensaje, redondeado a 16).",
                  "No ve el mensaje ni la llave."],
     _I("Mensaje", "Llave AES-256, IV de 16 bytes, relleno PKCS7", "Llave", "IV y texto cifrado",
        "Texto cifrado (múltiplo de 16 bytes)",
        "Sin MAC es maleable; IV repetido o predecible filtra información."))


# ------------------------------------------------------------------- GCM
def _alice_gcm(msg, p):
    r = cifrar_gcm(msg, p["aad"])
    return r, {"llave": r["componentes_secretos"]["llave"]}


def _bob_gcm(pub, ctx):
    r = descifrar_gcm(pub["nonce"], pub["texto_cifrado"], pub["etiqueta"], pub["datos_asociados"], ctx["llave"])
    return _res(r["aceptado"], r["texto"], r["explicacion"])


_reg("AES-256-GCM (autenticado)", "Cifrado simétrico", "Cifrado simétrico por bloques",
     _alice_gcm, _bob_gcm,
     [_atk("Alterar el texto cifrado", lambda pub, p: ({**pub, "texto_cifrado": _xor_hex(pub["texto_cifrado"], 0, 1)}, {}),
           False, "La etiqueta ya no coincide: InvalidTag."),
      _atk("Alterar los datos asociados (AAD)", lambda pub, p: ({**pub, "datos_asociados": pub["datos_asociados"] + "1"}, {}),
           False, "Los AAD viajan en claro pero están autenticados."),
      _atk("Alterar la etiqueta", lambda pub, p: ({**pub, "etiqueta": _xor_hex(pub["etiqueta"], 0, 1)}, {}),
           False, "Una etiqueta falsa no verifica.")],
     lambda pub: [f"Ve nonce, texto cifrado ({len(pub['texto_cifrado'])//2} bytes), etiqueta y AAD '{pub['datos_asociados']}'.",
                  "No ve el mensaje ni la llave."],
     _I("Mensaje y datos asociados (AAD)", "Llave AES-256, nonce de 12 bytes, etiqueta de 16 bytes",
        "Llave", "Nonce, texto cifrado, etiqueta y AAD", "Texto cifrado + etiqueta",
        "Repetir un nonce con la misma llave rompe la confidencialidad y la autenticidad."),
     opciones={"aad": {"tipo": "texto", "defecto": "id=42"}})


# ------------------------------------------------------------------ FLUJO
def _factory_flujo(cifrar, nombre_corto):
    def alice(msg, p):
        r = cifrar(msg)
        return r, {"llave": r["componentes_secretos"]["llave"]}

    def bob(pub, ctx):
        r = descifrar_flujo(nombre_corto, pub["texto_cifrado"], pub["nonce"], ctx["llave"])
        return _res(True, r["texto"], r["explicacion"])
    return alice, bob


def _reg_flujo(nombre, cifrar, corto):
    a, b = _factory_flujo(cifrar, corto)
    _reg(nombre, "Cifrado simétrico", "Cifrado por flujo (stream cipher)", a, b,
         [_atk("Alterar un byte del texto cifrado", lambda pub, p: ({**pub, "texto_cifrado": _xor_hex(pub["texto_cifrado"], 0, 1)}, {}),
               True, "El cambio se refleja directamente en el texto claro; Bob no lo detecta.")],
         lambda pub: [f"Ve nonce y texto cifrado de {len(pub['texto_cifrado'])//2} bytes (= tamaño exacto del mensaje).",
                      "No ve el mensaje ni la llave."],
         _I("Mensaje", "Llave de 256 bits, nonce de 16 bytes", "Llave", "Nonce y texto cifrado",
            "Texto cifrado (mismo largo que el mensaje)",
            "Reutilizar (llave, nonce) permite XOR de dos textos cifrados; sin MAC es alterable."))


_reg_flujo("ChaCha20 (sin autenticación)", cifrar_chacha20, "ChaCha20")
_reg_flujo("AES-256-CTR (sin autenticación)", cifrar_aes_ctr, "AES-CTR")


# -------------------------------------------------------------------- MAC
def _factory_mac(calc, ver):
    def alice(msg, p):
        r = calc(msg)
        return r, {"llave": r["componentes_secretos"]["llave"]}

    def bob(pub, ctx):
        r = ver(pub["mensaje"], pub["etiqueta"], ctx["llave"])
        return _res(r["aceptado"], pub["mensaje"] if r["aceptado"] else None, r["explicacion"])
    return alice, bob


def _a_mac_mod(pub, p):
    return {**pub, "mensaje": pub["mensaje"] + "!"}, {}


def _a_mac_rand(pub, p):
    return {**pub, "etiqueta": os.urandom(len(bytes.fromhex(pub["etiqueta"]))).hex()}, {}


def _a_mac_sha(pub, p):
    import hashlib
    m = pub["mensaje"] + "!"
    return {"mensaje": m, "etiqueta": hashlib.sha256(m.encode()).hexdigest()[:len(pub["etiqueta"])]}, {}


def _reg_mac(nombre, calc, ver):
    a, b = _factory_mac(calc, ver)
    _reg(nombre, "Cifrado simétrico", "Códigos de Autenticación de mensajes", a, b,
         [_atk("Modificar el mensaje (etiqueta original)", _a_mac_mod, False, "La etiqueta original deja de ser válida."),
          _atk("Poner una etiqueta aleatoria", _a_mac_rand, False, "Adivinar una etiqueta es inviable."),
          _atk("Recalcular la etiqueta con un hash simple", _a_mac_sha, False,
               "Sin la llave, Eve no puede producir una etiqueta válida.")],
         lambda pub: [f"Ve el mensaje completo y la etiqueta ({len(pub['etiqueta'])//2} bytes).",
                      "No puede fabricar etiquetas sin la llave; sí puede reenviar paquetes válidos (repetición)."],
         _I("Mensaje", "Llave secreta compartida", "Llave", "Mensaje y etiqueta", "Etiqueta de autenticación",
            "Sin contador/nonce no impide repetición; comparar con == abre ataques de tiempo."))


_reg_mac("HMAC-SHA256", calcular_hmac, verificar_hmac)
_reg_mac("CMAC-AES", calcular_cmac, verificar_cmac)


# -------------------------------------------------------------------- KDF
def _alice_kdf(msg, p):
    r = derivar_scrypt(msg) if p["algoritmo"] == "Scrypt" else derivar_pbkdf2(msg)
    r["componentes_publicos"] = {**r["componentes_publicos"], "verificador": r["salida"]}
    return r, {"contrasena": msg}


def _derivar_kdf(contrasena, pub, alg):
    sal = bytes.fromhex(pub["sal"])
    if alg == "Scrypt":
        return derivar_scrypt(contrasena, sal, pub["n"], pub["r"], pub["p"])["salida"]
    return derivar_pbkdf2(contrasena, sal, pub["iteraciones"])["salida"]


def _bob_kdf(pub, ctx):
    ok = _derivar_kdf(ctx["contrasena"], pub, ctx["params"]["algoritmo"]) == pub["verificador"]
    return _res(ok, None, "La contraseña produce el mismo verificador: acceso concedido." if ok
                else "RECHAZADO: con esa sal/verificador la contraseña no coincide.")


_reg("KDF: Scrypt / PBKDF2", "Cifrado simétrico", "Derivaciones de claves (KDF)", _alice_kdf, _bob_kdf,
     [_atk("Cambiar la sal", lambda pub, p: ({**pub, "sal": os.urandom(16).hex()}, {}), False,
           "Con otra sal se deriva otra clave: no coincide."),
      _atk("Alterar el verificador", lambda pub, p: ({**pub, "verificador": _xor_hex(pub["verificador"])}, {}), False,
           "El verificador alterado no coincide.")],
     lambda pub: ["Ve sal, parámetros de costo y verificador (por ejemplo, tras la filtración de una base de datos de prueba).",
                  "No ve la contraseña; solo puede adivinarla probando candidatos (cada intento cuesta trabajo del KDF)."],
     _I("Contraseña (el 'mensaje' de Alice)", "Sal aleatoria (16 bytes), parámetros de costo (n,r,p o iteraciones)",
        "Contraseña", "Sal, parámetros y verificador", "Clave derivada / verificador",
        "Sin sal o con costo bajo, el ataque de diccionario es barato; HKDF no sirve para contraseñas."),
     opciones={"algoritmo": {"tipo": "seleccion", "valores": ["Scrypt", "PBKDF2"], "defecto": "Scrypt"}},
     pasivo=("Ataque de diccionario contra el verificador",
             lambda pub, p: _dicc(lambda w: _derivar_kdf(w, pub, p["algoritmo"]) == pub["verificador"])))


# -------------------------------------------------------------------- RSA
def _alice_rsa(msg, p):
    r = cifrar_rsa(msg)
    return r, {"llave_privada": r["componentes_secretos"]["llave_privada"]}


def _bob_rsa(pub, ctx):
    r = descifrar_rsa(pub["texto_cifrado"], ctx["llave_privada"])
    return _res(r["aceptado"], r["texto"], r["explicacion"])


_reg("RSA-2048-OAEP", "Cifrado asimétrico", "Cifrado de clave pública", _alice_rsa, _bob_rsa,
     [_atk("Alterar el texto cifrado", lambda pub, p: ({**pub, "texto_cifrado": _xor_hex(pub["texto_cifrado"], 5, 1)}, {}),
           False, "OAEP detecta la alteración al descifrar.")],
     lambda pub: ["Ve la llave pública de Bob y un texto cifrado de 256 bytes.",
                  "Puede cifrar mensajes propios con la pública, pero no descifrar el de Alice.",
                  "Solo sabe que la pública es de Bob si está certificada (PKI)."],
     _I("Mensaje (máx. 190 bytes)", "Par de llaves RSA-2048, relleno OAEP", "Llave privada de Bob",
        "Llave pública y texto cifrado", "Texto cifrado de 256 bytes",
        "Mensajes largos (usar cifrado híbrido), RSA sin padding, llaves cortas o no autenticadas."))


# ----------------------------------------------------------------- FIRMAS
def _factory_firma(alg):
    def alice(msg, p):
        r = firmar(msg, alg)
        return r, {"llave_publica_confiable": r["componentes_publicos"]["llave_publica"]}

    def bob(pub, ctx):
        llave = ctx["llave_publica_confiable"] if ctx["params"]["autenticar_llave"] else pub["llave_publica"]
        r = verificar_firma(pub["mensaje"], pub["firma"], llave, alg)
        return _res(r["aceptado"], pub["mensaje"] if r["aceptado"] else None, r["explicacion"])

    def sustituir(pub, p):
        return firmar("Mensaje falso de Eve", alg)["componentes_publicos"], {}
    return alice, bob, sustituir


def _reg_firma(nombre, alg):
    a, b, sust = _factory_firma(alg)
    _reg(nombre, "Cifrado asimétrico", "Firmas digitales", a, b,
         [_atk("Modificar el mensaje firmado", lambda pub, p: ({**pub, "mensaje": pub["mensaje"] + "!"}, {}), False,
               "La firma deja de verificarse."),
          _atk("Eve firma su mensaje y sustituye la llave pública", sust,
               lambda p: not p["autenticar_llave"],
               "Funciona solo si Bob NO tiene autenticada la llave pública de Alice (por eso existe la PKI).")],
         lambda pub: ["Ve el mensaje, la firma y la llave pública de Alice.",
                      "No puede firmar como Alice; sí podría presentar su propia llave pública si Bob no la tiene autenticada."],
         _I("Mensaje", "Par de llaves (privada para firmar, pública para verificar)", "Llave privada de Alice",
            "Mensaje, firma y llave pública", "Firma digital",
            "Llave pública sin autenticar, llave privada filtrada, RSA sin PSS o con llaves cortas."),
         opciones={"autenticar_llave": {"tipo": "bool", "defecto": True}})


_reg_firma("Firma digital Ed25519", "Ed25519")
_reg_firma("Firma digital RSA-PSS", "RSA-PSS")


# -------------------------------------------------------------- X25519
def _dh(priv_hex, pub_hex):
    p = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return derivar_clave(p.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))))


def _alice_x(msg, p):
    def _gen():
        return x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    (a, b), metricas = medir(_gen)
    pa, pb = pub_bytes(a).hex(), pub_bytes(b).hex()
    ka = _dh(a.private_bytes_raw().hex(), pb)
    metricas.update(bytes_entrada=32, bytes_salida=len(ka))
    res = {"mecanismo": "Acuerdo de claves X25519 (sin autenticar)", "entradas": {"mensaje": "(no se cifra)"},
           "componentes_publicos": {"publica_alice": pa, "publica_bob": pb},
           "componentes_secretos": {"privada_alice": a.private_bytes_raw().hex(), "privada_bob": b.private_bytes_raw().hex()},
           "salida": ka.hex(), "propiedad": "Establecimiento de claves (NO autentica a los participantes)",
           "metricas": metricas,
           "condiciones": "Llaves efímeras por sesión, derivar con HKDF y AUTENTICAR los valores públicos."}
    return res, {"privada_alice": a.private_bytes_raw().hex(), "privada_bob": b.private_bytes_raw().hex()}


def _bob_x(pub, ctx):
    ka = _dh(ctx["privada_alice"], pub["publica_bob"])
    kb = _dh(ctx["privada_bob"], pub["publica_alice"])
    ok = ka == kb
    return _res(True, None,
                "Alice y Bob derivaron la MISMA clave." if ok else
                "Bob aceptó el valor público sin poder verificarlo: Alice y Bob NO comparten clave (hay un intermediario).",
                detalle={"claves_coinciden": ok}, _interno={"clave_alice": ka.hex(), "clave_bob": kb.hex()})


def _a_mitm(pub, p):
    e1, e2 = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    pub2 = {"publica_alice": pub_bytes(e1).hex(), "publica_bob": pub_bytes(e2).hex()}
    k_bob = _dh(e1.private_bytes_raw().hex(), pub["publica_bob"])      # clave que Eve comparte con Bob
    k_alice = _dh(e2.private_bytes_raw().hex(), pub["publica_alice"])  # clave que Eve comparte con Alice
    return pub2, {"clave_eve_con_bob": k_bob.hex(), "clave_eve_con_alice": k_alice.hex()}


def _post_x(res, pub2, meta, ctx):
    if meta and "_interno" in res:
        i = res["_interno"]
        res["detalle"]["eve_conoce_clave_de_bob"] = meta["clave_eve_con_bob"] == i["clave_bob"]
        res["detalle"]["eve_conoce_clave_de_alice"] = meta["clave_eve_con_alice"] == i["clave_alice"]
    return res


_reg("X25519 sin autenticar", "Cifrado asimétrico", "Intercambios de claves", _alice_x, _bob_x,
     [_atk("Man-in-the-middle: Eve sustituye los valores públicos", _a_mitm, True,
           "Bob no puede notar la sustitución; Eve comparte una clave con cada lado.",
           verifica=lambda r: (not r["detalle"]["claves_coinciden"]) and r["detalle"]["eve_conoce_clave_de_bob"]
           and r["detalle"]["eve_conoce_clave_de_alice"])],
     lambda pub: ["Ve las dos llaves públicas de 32 bytes.",
                  "No puede calcular el secreto compartido solo observando (problema Diffie-Hellman).",
                  "Sí puede sustituir los valores públicos si nadie los autentica."],
     _I("Ninguna (se acuerda una clave)", "Par efímero de cada lado (X25519), HKDF", "Llaves privadas efímeras",
        "Llaves públicas efímeras", "Clave compartida derivada",
        "Sin autenticar los valores públicos: man-in-the-middle."),
     post=_post_x)


def _alice_xf(msg, p):
    a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    ida, idb = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    pa, pb = pub_bytes(a), pub_bytes(b)
    pub = {"publica_alice": pa.hex(), "firma_alice": ida.sign(pa).hex(),
           "publica_bob": pb.hex(), "firma_bob": idb.sign(pb).hex()}
    ka = _dh(a.private_bytes_raw().hex(), pb.hex())
    res = {"mecanismo": "X25519 + firmas Ed25519", "entradas": {"mensaje": "(no se cifra)"},
           "componentes_publicos": pub,
           "componentes_secretos": {"privada_alice": a.private_bytes_raw().hex(), "privada_bob": b.private_bytes_raw().hex(),
                                    "identidad_privada_alice": "(oculta)", "identidad_privada_bob": "(oculta)"},
           "salida": ka.hex(), "propiedad": "Establecimiento de claves autenticado",
           "metricas": {"bytes_entrada": 32, "bytes_salida": len(ka)},
           "condiciones": "Las llaves de identidad deben conocerse/certificarse de antemano (PKI)."}
    ctx = {"privada_alice": a.private_bytes_raw().hex(), "privada_bob": b.private_bytes_raw().hex(),
           "id_pub_alice": ida.public_key().public_bytes_raw().hex(), "id_pub_bob": idb.public_key().public_bytes_raw().hex()}
    return res, ctx


def _firma_ok(id_pub_hex, firma_hex, valor_hex):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(id_pub_hex)).verify(
            bytes.fromhex(firma_hex), bytes.fromhex(valor_hex))
        return True
    except InvalidSignature:
        return False


def _bob_xf(pub, ctx):
    fa = _firma_ok(ctx["id_pub_alice"], pub["firma_alice"], pub["publica_alice"])
    fb = _firma_ok(ctx["id_pub_bob"], pub["firma_bob"], pub["publica_bob"])
    if not (fa and fb):
        return _res(False, None, "RECHAZADO: la firma del valor público no verifica con la identidad conocida. "
                    "Se detecta la sustitución (MITM).", detalle={"firma_alice_valida": fa, "firma_bob_valida": fb})
    ok = _dh(ctx["privada_alice"], pub["publica_bob"]) == _dh(ctx["privada_bob"], pub["publica_alice"])
    return _res(True, None, "Valores públicos autenticados: Alice y Bob comparten la misma clave.",
                detalle={"firma_alice_valida": fa, "firma_bob_valida": fb, "claves_coinciden": ok})


def _a_mitm_firmado(pub, p):
    e1, e2 = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    eid = ed25519.Ed25519PrivateKey.generate()
    p1, p2 = pub_bytes(e1), pub_bytes(e2)
    return {"publica_alice": p1.hex(), "firma_alice": eid.sign(p1).hex(),
            "publica_bob": p2.hex(), "firma_bob": eid.sign(p2).hex()}, {}


_reg("X25519 + firmas (autenticado)", "Cifrado asimétrico", "Intercambios de claves", _alice_xf, _bob_xf,
     [_atk("MITM firmando con la llave de identidad de Eve", _a_mitm_firmado, False,
           "Eve no tiene la llave de identidad de Alice/Bob: las firmas no verifican.")],
     lambda pub: ["Ve valores públicos y firmas.", "No puede producir firmas válidas de Alice ni de Bob."],
     _I("Ninguna (se acuerda una clave)", "Pares efímeros X25519 + llaves de identidad Ed25519",
        "Llaves privadas (efímeras y de identidad)", "Valores públicos y firmas", "Clave compartida autenticada",
        "Identidades no verificadas de antemano o llaves de identidad filtradas."))


# -------------------------------------------------------------------- PKI
def _alice_pki(msg, p):
    ca_k, ca = crear_ca("CA Confiable")
    srv = ed25519.Ed25519PrivateKey.generate()
    cert = emitir_certificado(ca_k, ca, "alice.ejemplo.mx", srv.public_key())
    res = {"mecanismo": "PKI: certificado X.509", "entradas": {"sujeto": "alice.ejemplo.mx"},
           "componentes_publicos": {"certificado": cert_pem(cert)},
           "componentes_secretos": {"llave_privada_ca": "(oculta)", "llave_privada_alice": "(oculta)"},
           "salida": cert_pem(cert)[:60] + "...", "propiedad": "Autenticación de la llave pública (identidad ligada a la llave)",
           "metricas": {"bytes_entrada": len(b"alice.ejemplo.mx"), "bytes_salida": len(cert_pem(cert))},
           "condiciones": "El receptor solo confía en las CAs de su almacén; revisar vigencia, nombre y firma."}
    return res, {"almacen_confianza": [cert_pem(ca)], "nombre_esperado": "alice.ejemplo.mx"}


def _bob_pki(pub, ctx):
    cert = x509.load_pem_x509_certificate(pub["certificado"].encode())
    almacen = [x509.load_pem_x509_certificate(c.encode()) for c in ctx["almacen_confianza"]]
    r = verificar_certificado(cert, almacen, ctx["nombre_esperado"])
    return _res(r["aceptado"], None, r["explicacion"])


def _a_pki_falsa(pub, p):
    k, ca_mala = crear_ca("CA Confiable")           # mismo nombre, otra llave
    cert = emitir_certificado(k, ca_mala, "alice.ejemplo.mx", ed25519.Ed25519PrivateKey.generate().public_key())
    return {"certificado": cert_pem(cert)}, {}


def _a_pki_alterar(pub, p):
    c = x509.load_pem_x509_certificate(pub["certificado"].encode())
    der = bytearray(c.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    return {"certificado": cert_pem(x509.load_der_x509_certificate(bytes(der)))}, {}


_reg("PKI: certificado X.509", "Cifrado asimétrico", "Infraestructura de clave publica (PKI)", _alice_pki, _bob_pki,
     [_atk("Certificado de una CA no confiable (mismo nombre)", _a_pki_falsa, False,
           "El nombre de la CA no basta: la firma no verifica con la CA que Bob conoce."),
      _atk("Alterar el certificado", _a_pki_alterar, False, "La firma de la CA deja de verificar.")],
     lambda pub: ["Ve el certificado completo (es público).",
                  "No puede emitir certificados válidos sin la llave privada de una CA de confianza."],
     _I("Nombre del sujeto y su llave pública", "CA raíz, certificado X.509, almacén de confianza",
        "Llave privada de la CA y del sujeto", "Certificado de la CA y del sujeto", "Certificado firmado",
        "Confiar en CAs desconocidas, no revisar vigencia o nombre, perder la llave privada de la CA."))


# --------------------------------------------------------------- consultas
def categorias():
    orden = ["Cifrados sin uso de llaves", "Cifrado simétrico", "Cifrado asimétrico"]
    return orden


def apartados(categoria):
    vistos = []
    for m in REGISTRO.values():
        if m["categoria"] == categoria and m["apartado"] not in vistos:
            vistos.append(m["apartado"])
    return vistos


def variantes(categoria, apartado):
    return [n for n, m in REGISTRO.items() if m["categoria"] == categoria and m["apartado"] == apartado]
