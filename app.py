"""Laboratorio educativo de criptografía: Alice, Bob y Eve.
Ejecutar con:  streamlit run app.py"""
import streamlit as st

from mecanismos.registro import REGISTRO, categorias, apartados, variantes, ejecutar_alice, entregar
from tabla import construir_tabla, a_markdown
from ataques.diccionario import ataque_diccionario, sha256_hex, CONTRASENA_DEBIL, CONTRASENA_FUERTE
from ataques.comparar_kdf import intentos_por_segundo_sha256, intentos_por_segundo_scrypt
from ataques.manipulacion import (alterar_sin_autenticacion, alterar_gcm_texto_cifrado,
                                  alterar_gcm_datos_asociados, reutilizacion_de_nonce)
from ataques.mac_y_repeticion import (modificar_mensaje_con_mac, repeticion_sin_proteccion,
                                      repeticion_con_contador)
from ataques.escenarios_asimetricos import (modificar_mensaje_firmado, mitm_sin_autenticacion,
                                            mitm_con_firmas, pki_ca_no_confiable)
from ataques.filtracion import filtracion_gcm, filtracion_hmac, filtracion_firma, filtracion_rsa

st.set_page_config(page_title="Laboratorio de criptografía", page_icon="🔐", layout="wide")

NOTA_MEMORIA = ("**Limitación:** la memoria se mide con `tracemalloc`, que solo ve las asignaciones de Python. "
                "No incluye la memoria que reservan las bibliotecas nativas (p. ej. OpenSSL, usada por `cryptography`). "
                "Por ejemplo, Scrypt usa ~16 MiB reales y aquí aparece casi en 0 KB.")
SIN_CONTADOR = {"KDF: Scrypt / PBKDF2", "X25519 sin autenticar", "X25519 + firmas (autenticado)", "PKI: certificado X.509"}
SIN_MENSAJE = {"X25519 sin autenticar", "X25519 + firmas (autenticado)", "PKI: certificado X.509"}
ACCION_ALICE = {
    "Funciones hash criptográficas": "Calcular huella", "Construcción esponja y salida extensible": "Calcular salida",
    "Cifrado simétrico por bloques": "Cifrar", "Cifrado por flujo (stream cipher)": "Cifrar",
    "Códigos de Autenticación de mensajes": "Autenticar (calcular etiqueta)", "Derivaciones de claves (KDF)": "Derivar clave",
    "Cifrado de clave pública": "Cifrar", "Firmas digitales": "Firmar",
    "Intercambios de claves": "Iniciar acuerdo de claves", "Infraestructura de clave publica (PKI)": "Emitir certificado",
}
ETIQUETAS = {"autenticar_llave": "Bob ya tiene autenticada (certificada) la llave pública de Alice",
             "aad": "Datos asociados (AAD)", "algoritmo": "Algoritmo", "variante": "Variante", "longitud": "Longitud de salida (bytes)"}


# ------------------------------------------------------------------ paneles
def _contador_bob(res, pkt):
    """Control extra anti-repetición: Bob exige un contador creciente dentro del mensaje autenticado."""
    if not pkt["contador"] or not res["aceptado"] or not res.get("texto"):
        return res
    try:
        n = int(res["texto"].split("|", 1)[0])
    except ValueError:
        return {**res, "aceptado": False, "texto": None, "explicacion": "RECHAZADO: el mensaje no trae contador."}
    if n <= st.session_state.ultimo_bob:
        return {**res, "aceptado": False, "texto": None,
                "explicacion": f"RECHAZADO por repetición: el contador {n} ya fue usado (último = {st.session_state.ultimo_bob})."}
    st.session_state.ultimo_bob = n
    return res


def panel_alice(nombre, m):
    st.markdown("### 👩 Alice (emisor)")
    es_pwd = nombre.startswith("KDF")
    if nombre in SIN_MENSAJE:
        st.caption("Este mecanismo no cifra un mensaje: establece una clave o un certificado.")
        msg = "(sin mensaje)"
    else:
        msg = st.text_area("Contraseña de práctica" if es_pwd else "Mensaje", "Hola Bob, nos vemos a las 5",
                           key=f"msg_{nombre}", height=80)
    params = {}
    for k, o in m["opciones"].items():
        key, etq = f"opt_{nombre}_{k}", ETIQUETAS.get(k, k)
        if o["tipo"] == "seleccion":
            params[k] = st.selectbox(etq, o["valores"], key=key)
        elif o["tipo"] == "numero":
            params[k] = int(st.number_input(etq, o["min"], o["max"], o["defecto"], key=key))
        elif o["tipo"] == "texto":
            params[k] = st.text_input(etq, o["defecto"], key=key)
        else:
            params[k] = st.checkbox(etq, o["defecto"], key=key)
    contador = False
    if nombre not in SIN_CONTADOR:
        contador = st.checkbox("Añadir contador anti-repetición (Alice envía 'N|mensaje')", key=f"cnt_{nombre}")
    if st.button(f"▶ {ACCION_ALICE[m['apartado']]}", key=f"btn_alice_{nombre}", type="primary"):
        enviado = msg
        if contador:
            st.session_state.contador_alice += 1
            enviado = f"{st.session_state.contador_alice}|{msg}"
        try:
            res, ctx = ejecutar_alice(nombre, enviado, params)
            st.session_state.pkt = {"resultado": res, "ctx": ctx, "contador": contador, "enviado": enviado}
            st.session_state.resultado_bob = None
        except ValueError as e:
            st.error(f"Uso incorrecto detectado: {e}")
    pkt = st.session_state.pkt
    if pkt:
        r = pkt["resultado"]
        st.markdown(f"**{r['mecanismo']}** — componentes que Alice envía a Bob:")
        st.json(r["componentes_publicos"], expanded=False)
        with st.expander("🔑 Secretos (solo Alice y Bob; NUNCA llegan a Eve)"):
            st.json(r["componentes_secretos"], expanded=False)


def panel_eve(nombre, m):
    st.markdown("### 😈 Eve (observador / atacante simulado)")
    pkt = st.session_state.pkt
    if not pkt:
        st.info("Eve espera a que Alice envíe algo por el canal.")
        return
    pub = pkt["resultado"]["componentes_publicos"]
    st.markdown("**Eve observa en el canal (solo datos públicos):**")
    st.json(pub, expanded=False)
    ocultos = ", ".join(pkt["resultado"]["componentes_secretos"].keys()) or "ninguno"
    st.caption(f"🔒 Eve NO recibe: {ocultos}, ni lo que Bob ya posee de antemano.")
    st.markdown("**Información que Eve logra obtener:**")
    for linea in m["eve_obtiene"](pub):
        st.markdown(f"- {linea}")
    acciones = ["Dejar pasar sin cambios", "Reenviar el paquete original (repetición)"] + [a["nombre"] for a in m["ataques"]]
    accion = st.selectbox("Acción de laboratorio de Eve", acciones, key=f"eve_{nombre}")
    ataque = next((a for a in m["ataques"] if a["nombre"] == accion), None)
    if ataque:
        st.caption(ataque["descripcion"])
    if st.button("📨 Eve entrega a Bob", key=f"btn_eve_{nombre}"):
        res = _contador_bob(entregar(nombre, pub, pkt["ctx"], ataque), pkt)
        st.session_state.resultado_bob = {"res": res, "accion": accion, "ataque": ataque}
    if m["pasivo"]:
        titulo, fn = m["pasivo"]
        if st.button(f"🔍 {titulo}", key=f"btn_pasivo_{nombre}"):
            with st.spinner("Eve probando candidatos..."):
                r = fn(pub, pkt["ctx"]["params"])
            st.json(r)
            st.caption("Eve NO descifró nada: adivinó candidatos hasta que uno produjo el mismo resultado.")


def panel_bob(nombre, m):
    st.markdown("### 👨 Bob (receptor)")
    rb = st.session_state.resultado_bob
    if not rb:
        st.info("Bob espera un paquete. Usa el botón de Eve para entregárselo.")
        return
    res, ataque, accion = rb["res"], rb["ataque"], rb["accion"]
    st.markdown("**Bob recibió:**")
    st.json(res["pub_entregado"], expanded=False)
    (st.success if res["aceptado"] else st.error)("✅ ACEPTADO" if res["aceptado"] else "⛔ RECHAZADO")
    st.write(res["explicacion"])
    if res.get("texto"):
        st.markdown("Mensaje obtenido:")
        st.code(res["texto"], language=None)
    if res.get("detalle"):
        st.json(res["detalle"])
    if ataque and res["aceptado"]:
        st.warning("⚠️ La manipulación NO fue detectada: usado así, este mecanismo no protege contra esa acción de Eve.")
    elif ataque:
        st.info(f"🛡️ Control que detectó la manipulación: {ataque['descripcion']}")
    elif accion.startswith("Reenviar"):
        (st.warning if res["aceptado"] else st.info)(
            "⚠️ Bob aceptó la repetición: se necesita contador/nonce." if res["aceptado"]
            else "🛡️ El contador anti-repetición detectó el reenvío.")


def preguntas(nombre, m):
    pkt = st.session_state.pkt
    st.divider()
    st.markdown("## 📚 Las cuatro preguntas")
    c1, c2, c3, c4 = st.columns(4)
    i = m["info"]
    with c1:
        st.markdown("**¿Qué protección proporciona?**")
        st.write(pkt["resultado"]["propiedad"] if pkt else "Ejecuta la operación de Alice para verlo.")
    with c2:
        st.markdown("**¿Qué componentes necesita?**")
        st.write(f"**Entradas:** {i['entradas']}")
        st.write(f"**Componentes:** {i['componentes']}")
        st.write(f"**Secreto:** {i['secreto']}")
        st.write(f"**Público:** {i['publico']}")
        st.write(f"**Salidas:** {i['salidas']}")
    with c3:
        st.markdown("**¿Qué recursos consume?**")
        if pkt:
            st.json(pkt["resultado"]["metricas"])
        else:
            st.write("Ejecuta la operación de Alice para medirlo.")
        st.caption(NOTA_MEMORIA)
    with c4:
        st.markdown("**¿Qué pasa si se usa incorrectamente?**")
        st.write(i["mal_uso"])
        if pkt:
            st.write(f"**Condiciones de uso:** {pkt['resultado']['condiciones']}")


def pantalla_mecanismo(nombre):
    m = REGISTRO[nombre]
    if st.session_state.get("mec_actual") != nombre:
        st.session_state.update(mec_actual=nombre, pkt=None, resultado_bob=None, contador_alice=0, ultimo_bob=0)
    st.subheader(f"{m['apartado']} — {nombre}")
    st.caption("Flujo: Alice → canal (Eve observa y puede manipular) → Bob")
    ca, ce, cb = st.columns(3)
    with ca:
        panel_alice(nombre, m)
    with ce:
        panel_eve(nombre, m)
    with cb:
        panel_bob(nombre, m)
    preguntas(nombre, m)


# ------------------------------------------------------------- laboratorio
def esc_diccionario():
    for etq, pwd in (("DÉBIL", CONTRASENA_DEBIL), ("FUERTE", CONTRASENA_FUERTE)):
        h = sha256_hex(pwd)
        st.write(f"**Contraseña {etq}** — hash que ve Eve: `{h}`")
        st.json(ataque_diccionario(h), expanded=True)
    st.caption("Eve no descifró el hash: adivinó una contraseña presente en el diccionario.")


def esc_kdf():
    with st.spinner("Eve intenta adivinar durante unos segundos..."):
        s, k = intentos_por_segundo_sha256(), intentos_por_segundo_scrypt()
    st.table([s, k])
    st.success(f"SHA-256 directo es ~{s['intentos_por_seg'] / k['intentos_por_seg']:,.0f} veces más fácil de atacar que Scrypt.")


def esc_sin_autenticacion():
    r = alterar_sin_autenticacion()
    st.json(r)
    st.caption("Eve no conoce la llave y aun así cambió $100 por $900; Bob lo aceptó.")
    n = reutilizacion_de_nonce()
    st.write("Mal uso extra: reutilizar el nonce →", n)


def esc_gcm():
    st.write("Texto cifrado alterado:"); st.json(alterar_gcm_texto_cifrado())
    st.write("Datos asociados alterados:"); st.json(alterar_gcm_datos_asociados())


def esc_mac():
    st.json(modificar_mensaje_con_mac())


def esc_firma():
    for alg in ("Ed25519", "RSA-PSS"):
        r = modificar_mensaje_firmado(alg)
        st.write(f"**{alg}** — original: {r['original']['aceptado']} | alterado: {r['alterado']['aceptado']}")
        st.caption(r["alterado"]["explicacion"])


def esc_dh():
    st.write("Sin autenticar:"); st.json(mitm_sin_autenticacion())
    st.write("Con firmas de identidad:"); st.json(mitm_con_firmas())


def esc_repeticion():
    st.write("Bob solo verifica HMAC:")
    for i, (ok, t) in enumerate(repeticion_sin_proteccion(), 1):
        st.write(f"Envío {i}: aceptado={ok} — {t}")
    st.write("Bob verifica HMAC + contador:")
    for i, (ok, t) in enumerate(repeticion_con_contador(), 1):
        st.write(f"Envío {i}: aceptado={ok} — {t}")


def esc_pki():
    st.json(pki_ca_no_confiable())


ESCENARIOS = [
    ("1. Contraseña débil", "Probar un diccionario pequeño contra un hash de prueba",
     "Recuperar una contraseña por conjeturas no equivale a descifrar un hash", esc_diccionario),
    ("2. Derivación de contraseñas", "Comparar intentos contra SHA-256 directo y Scrypt",
     "Los parámetros de costo afectan el trabajo de cada intento", esc_kdf),
    ("3. Cifrado sin autenticación", "Alterar bytes de un mensaje cifrado",
     "El cifrado por sí solo no garantiza detección de modificaciones", esc_sin_autenticacion),
    ("4. Cifrado autenticado", "Alterar el cifrado o los datos asociados de AES-GCM",
     "La verificación debe fallar", esc_gcm),
    ("5. HMAC o CMAC", "Modificar el mensaje sin conocer la llave",
     "La etiqueta original deja de ser válida", esc_mac),
    ("6. Firma digital", "Modificar un mensaje firmado", "La firma deja de verificarse", esc_firma),
    ("7. Acuerdo de claves sin autenticación", "Sustituir valores públicos en una simulación",
     "Un acuerdo de claves necesita autenticar a los participantes", esc_dh),
    ("8. Repetición de mensajes", "Reenviar un mensaje válido",
     "La autenticación necesita controles adicionales para impedir repeticiones", esc_repeticion),
    ("9. PKI", "Presentar un certificado de una CA no confiable", "El receptor debe rechazarlo", esc_pki),
]


def pantalla_laboratorio():
    st.subheader("🧪 Laboratorio de escenarios (datos creados para la práctica)")
    for titulo, accion, aprendizaje, fn in ESCENARIOS:
        with st.expander(titulo):
            st.write(f"**Acción de Eve:** {accion}")
            st.write(f"**Aprendizaje esperado:** {aprendizaje}")
            if st.button("Ejecutar escenario", key=f"esc_{titulo}"):
                fn()


def pantalla_filtracion():
    st.subheader("🗝️ Filtración de llaves (escenario separado y explícito)")
    st.warning("En todo el programa Eve NUNCA recibe llaves secretas o privadas. Aquí se **supone** que una llave "
               "se filtró (robo, malware, mala gestión) para mostrar la consecuencia.")
    casos = [("AES-GCM con llave filtrada", filtracion_gcm), ("HMAC con llave filtrada", filtracion_hmac),
             ("Firma Ed25519 con llave privada filtrada", filtracion_firma),
             ("RSA con llave privada filtrada", filtracion_rsa)]
    for titulo, fn in casos:
        with st.expander(titulo):
            if st.button("Simular filtración", key=f"fil_{titulo}"):
                st.json(fn())


@st.cache_data(show_spinner=False)
def _tabla():
    return construir_tabla()


def pantalla_tabla():
    st.subheader("📋 Tabla de mecanismos, componentes y propiedades")
    filas = _tabla()
    st.dataframe(filas, width="stretch")
    st.caption(NOTA_MEMORIA)
    st.download_button("⬇ Descargar tabla (Markdown)", a_markdown(filas), "tabla_mecanismos.md")


# --------------------------------------------------------------------- menú
st.title("🔐 Laboratorio de criptografía: Alice, Bob y Eve")
MENU = categorias() + ["Laboratorio de escenarios", "Filtración de llaves (escenario aparte)", "Tabla de mecanismos"]
with st.sidebar:
    st.header("Menú principal")
    opcion = st.radio("Apartado", MENU, key="menu")
    nombre_sel = None
    if opcion in categorias():
        ap = st.selectbox("Mecanismo", apartados(opcion), key=f"ap_{opcion}")
        vs = variantes(opcion, ap)
        nombre_sel = vs[0] if len(vs) == 1 else st.selectbox("Variante", vs, key=f"var_{ap}")
    st.divider()
    st.caption("Datos de práctica. Eve solo ve el canal; las filtraciones de llaves son un escenario aparte.")

if nombre_sel:
    pantalla_mecanismo(nombre_sel)
elif opcion == "Laboratorio de escenarios":
    pantalla_laboratorio()
elif opcion.startswith("Filtración"):
    pantalla_filtracion()
else:
    pantalla_tabla()
