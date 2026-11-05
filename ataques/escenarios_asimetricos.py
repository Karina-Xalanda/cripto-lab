"""Escenarios de Eve contra mecanismos asimétricos."""
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mecanismos.firmas import firmar, verificar_firma
from mecanismos.intercambio import pub_bytes, derivar_clave
from mecanismos.pki import crear_ca, emitir_certificado, verificar_certificado


def modificar_mensaje_firmado(algoritmo="Ed25519") -> dict:
    f = firmar("Transferir $100 a Bob", algoritmo)
    p = f["componentes_publicos"]
    return {"original": verificar_firma("Transferir $100 a Bob", p["firma"], p["llave_publica"], algoritmo),
            "alterado": verificar_firma("Transferir $900 a Bob", p["firma"], p["llave_publica"], algoritmo)}


def _x(priv, pub_raw):
    return derivar_clave(priv.exchange(x25519.X25519PublicKey.from_public_bytes(pub_raw)))


def mitm_sin_autenticacion() -> dict:
    """Eve sustituye los valores públicos de Alice y Bob por los suyos."""
    a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    e1, e2 = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    k_alice = _x(a, pub_bytes(e1))          # Alice cree que recibió la pública de Bob
    k_bob = _x(b, pub_bytes(e2))            # Bob cree que recibió la pública de Alice
    k_eve_alice, k_eve_bob = _x(e1, pub_bytes(a)), _x(e2, pub_bytes(b))
    nonce = b"0" * 12
    ct = AESGCM(k_alice).encrypt(nonce, b"Contrasena del banco: 1234", None)   # Alice cifra "seguro"
    leido_por_eve = AESGCM(k_eve_alice).decrypt(nonce, ct, None).decode()
    return {"alice_y_bob_comparten_clave": k_alice == k_bob,
            "eve_tiene_clave_de_alice": k_eve_alice == k_alice,
            "eve_tiene_clave_de_bob": k_eve_bob == k_bob,
            "mensaje_leido_por_eve": leido_por_eve}


def mitm_con_firmas() -> dict:
    """Bob firma su pública efímera con su llave de identidad (autenticada de antemano).
    Eve la sustituye, pero no puede falsificar la firma de Bob."""
    bob_id = ed25519.Ed25519PrivateKey.generate()
    bob_id_pub = bob_id.public_key()
    b, e = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    firma_bob = bob_id.sign(pub_bytes(b))                  # firma sobre la pública REAL de Bob
    valor_recibido = pub_bytes(e)                          # Eve sustituye el valor público
    from cryptography.exceptions import InvalidSignature
    try:
        bob_id_pub.verify(firma_bob, valor_recibido)
        return {"aceptado": True, "explicacion": "Alice aceptó (no debería)"}
    except InvalidSignature:
        return {"aceptado": False, "explicacion": "RECHAZADO: la firma de Bob no corresponde al valor público recibido. Se detecta el MITM."}


def pki_ca_no_confiable() -> dict:
    ca_ok_k, ca_ok = crear_ca("CA Confiable")
    ca_mal_k, ca_mal = crear_ca("CA Confiable")           # Eve usa el MISMO nombre
    bob_k = ed25519.Ed25519PrivateKey.generate()
    cert_legitimo = emitir_certificado(ca_ok_k, ca_ok, "bob.ejemplo.mx", bob_k.public_key())
    eve_k = ed25519.Ed25519PrivateKey.generate()
    cert_falso = emitir_certificado(ca_mal_k, ca_mal, "bob.ejemplo.mx", eve_k.public_key())
    almacen = [ca_ok]                                      # Alice solo confía en la CA legítima
    return {"legitimo": verificar_certificado(cert_legitimo, almacen, "bob.ejemplo.mx"),
            "falso": verificar_certificado(cert_falso, almacen, "bob.ejemplo.mx")}