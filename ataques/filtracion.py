"""ESCENARIO SEPARADO Y EXPLÍCITO: filtración de llaves.
Aquí SÍ se asume que Eve obtuvo la llave secreta/privada (robo, mala gestión, malware...).
En los demás escenarios Eve nunca recibe secretos."""
from cryptography.hazmat.primitives.asymmetric import ed25519
from mecanismos.bloques import cifrar_gcm, descifrar_gcm
from mecanismos.mac import calcular_hmac, verificar_hmac
from mecanismos.rsa_cifrado import cifrar_rsa, descifrar_rsa

ORIGINAL = "Transferir $100 a Bob"
FALSO = "Transferir $9999 a Eve"


def filtracion_gcm() -> dict:
    c = cifrar_gcm(ORIGINAL, aad="id=42")
    p, llave = c["componentes_publicos"], c["componentes_secretos"]["llave"]       # <- llave filtrada
    leido = descifrar_gcm(p["nonce"], p["texto_cifrado"], p["etiqueta"], p["datos_asociados"], llave)
    f = cifrar_gcm(FALSO, aad="id=42", llave=bytes.fromhex(llave))["componentes_publicos"]
    bob = descifrar_gcm(f["nonce"], f["texto_cifrado"], f["etiqueta"], f["datos_asociados"], llave)
    return {"llave_filtrada": llave[:16] + "...", "eve_lee_el_mensaje": leido["texto"],
            "mensaje_falso_de_eve": FALSO, "bob_acepta_el_falso": bob["aceptado"], "bob_lee": bob["texto"]}


def filtracion_hmac() -> dict:
    c = calcular_hmac(ORIGINAL)
    llave = c["componentes_secretos"]["llave"]                                       # <- llave filtrada
    falso = calcular_hmac(FALSO, llave=bytes.fromhex(llave))
    bob = verificar_hmac(FALSO, falso["salida"], llave)
    return {"llave_filtrada": llave[:16] + "...", "mensaje_falso_de_eve": FALSO,
            "etiqueta_falsificada": falso["salida"][:24] + "...", "bob_acepta_el_falso": bob["aceptado"]}


def filtracion_firma() -> dict:
    priv = ed25519.Ed25519PrivateKey.generate()                                      # <- se filtra esta llave privada
    pub = priv.public_key()
    from cryptography.exceptions import InvalidSignature
    firma_falsa = priv.sign(FALSO.encode())                                          # Eve firma como Alice
    try:
        pub.verify(firma_falsa, FALSO.encode())
        acepta = True
    except InvalidSignature:
        acepta = False
    return {"mensaje_falso_de_eve": FALSO, "firma_falsificada": firma_falsa.hex()[:24] + "...",
            "bob_acepta_el_falso": acepta,
            "nota": "La firma es válida: sin la llave privada protegida desaparece la autenticación y el no repudio."}


def filtracion_rsa() -> dict:
    c = cifrar_rsa(ORIGINAL)
    priv = c["componentes_secretos"]["llave_privada"]                                # <- llave privada filtrada
    r = descifrar_rsa(c["salida"], priv)
    return {"eve_lee_el_mensaje": r["texto"],
            "nota": "Quien tiene la llave privada de Bob descifra todo lo cifrado para él, incluso mensajes pasados."}
