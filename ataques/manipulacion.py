"""Escenarios de manipulación de Eve sobre mensajes cifrados."""
from mecanismos.flujo import cifrar_aes_ctr, descifrar_flujo
from mecanismos.bloques import cifrar_gcm, descifrar_gcm


def _xor_en(hex_str: str, posicion: int, delta: int) -> str:
    b = bytearray(bytes.fromhex(hex_str))
    b[posicion] ^= delta
    return b.hex()


def alterar_sin_autenticacion() -> dict:
    """AES-CTR: Eve NO conoce la llave, pero conoce el formato del mensaje.
    Cambia '$100' por '$900' haciendo XOR sobre el texto cifrado."""
    original = "Transferir $100 a Bob"
    pos = original.index("1")
    delta = ord("1") ^ ord("9")                     # lo que Eve necesita aplicar
    c = cifrar_aes_ctr(original)
    pub = c["componentes_publicos"]
    modificado = _xor_en(pub["texto_cifrado"], pos, delta)
    r = descifrar_flujo("AES-CTR", modificado, pub["nonce"], c["componentes_secretos"]["llave"])
    return {"original": original, "bob_recibe": r["texto"], "aceptado": r["aceptado"],
            "explicacion": r["explicacion"]}


def alterar_gcm_texto_cifrado() -> dict:
    c = cifrar_gcm("Transferir $100 a Bob", aad="id=42")
    p = c["componentes_publicos"]
    r = descifrar_gcm(p["nonce"], _xor_en(p["texto_cifrado"], 10, 0x08), p["etiqueta"],
                      p["datos_asociados"], c["componentes_secretos"]["llave"])
    return r


def alterar_gcm_datos_asociados() -> dict:
    c = cifrar_gcm("Transferir $100 a Bob", aad="id=42")
    p = c["componentes_publicos"]
    return descifrar_gcm(p["nonce"], p["texto_cifrado"], p["etiqueta"],
                         "id=43", c["componentes_secretos"]["llave"])


def reutilizacion_de_nonce() -> dict:
    """Mal uso: misma llave + mismo nonce en dos mensajes.
    XOR(cifrado1, cifrado2) == XOR(texto1, texto2): se filtra información sin tocar la llave."""
    import os
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    llave, nonce = os.urandom(32), os.urandom(16)

    def cif(m):
        e = Cipher(algorithms.AES(llave), modes.CTR(nonce)).encryptor()
        return e.update(m) + e.finalize()
    m1, m2 = b"ATACAR AL AMANECER", b"ATACAR AL ANOCHECER"[:18]
    c1, c2 = cif(m1), cif(m2)
    xor_cifrados = bytes(a ^ b for a, b in zip(c1, c2))
    xor_textos = bytes(a ^ b for a, b in zip(m1, m2))
    return {"xor_cifrados": xor_cifrados.hex(), "xor_textos": xor_textos.hex(),
            "iguales": xor_cifrados == xor_textos}