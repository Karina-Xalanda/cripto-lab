"""Escenarios: (1) Eve modifica un mensaje autenticado con MAC;
(2) Eve reenvía un mensaje válido (ataque de repetición)."""
import os
from mecanismos.mac import calcular_hmac, verificar_hmac, calcular_cmac, verificar_cmac


def modificar_mensaje_con_mac() -> dict:
    """Eve cambia el mensaje pero no puede recalcular la etiqueta (no tiene la llave)."""
    original, alterado = "Transferir $100 a Bob", "Transferir $900 a Bob"
    out = {}
    for nombre, calc, ver in (("HMAC-SHA256", calcular_hmac, verificar_hmac),
                              ("CMAC-AES", calcular_cmac, verificar_cmac)):
        c = calc(original)
        llave, etiqueta = c["componentes_secretos"]["llave"], c["salida"]
        out[nombre] = {
            "original_valido": ver(original, etiqueta, llave)["aceptado"],
            "alterado_valido": ver(alterado, etiqueta, llave)["aceptado"],
        }
    return out


class BobSinProteccion:
    """Solo verifica el HMAC. Acepta cualquier mensaje con etiqueta válida."""
    def __init__(self, llave_hex):
        self.llave = llave_hex

    def recibir(self, mensaje, etiqueta):
        r = verificar_hmac(mensaje, etiqueta, self.llave)
        return r["aceptado"], r["explicacion"]


class BobConContador:
    """Verifica el HMAC Y que el contador sea mayor que el último visto."""
    def __init__(self, llave_hex):
        self.llave = llave_hex
        self.ultimo = 0

    def recibir(self, mensaje, etiqueta):
        r = verificar_hmac(mensaje, etiqueta, self.llave)
        if not r["aceptado"]:
            return False, r["explicacion"]
        contador = int(mensaje.split("|", 1)[0])
        if contador <= self.ultimo:
            return False, f"RECHAZADO: contador {contador} ya usado (último = {self.ultimo}). Es una repetición."
        self.ultimo = contador
        return True, "Aceptado: etiqueta válida y contador nuevo."


def repeticion_sin_proteccion() -> list:
    msg = "Pagar $500 a Eve"
    c = calcular_hmac(msg)
    bob = BobSinProteccion(c["componentes_secretos"]["llave"])
    return [bob.recibir(msg, c["salida"]) for _ in range(3)]   # original + 2 reenvíos de Eve


def repeticion_con_contador() -> list:
    llave = os.urandom(32)
    bob = BobConContador(llave.hex())
    msg = "1|Pagar $500 a Eve"                  # el contador va DENTRO del mensaje autenticado
    c = calcular_hmac(msg, llave)
    return [bob.recibir(msg, c["salida"]) for _ in range(3)]