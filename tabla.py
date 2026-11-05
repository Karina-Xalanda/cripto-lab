"""Tabla de mecanismos, componentes y propiedades (entregable del reporte).
Uso:  python tabla.py   ->  genera tabla_mecanismos.md"""
from mecanismos.registro import REGISTRO, ejecutar_alice

MSG = "Hola Bob, nos vemos a las 5"


def construir_tabla() -> list:
    filas = []
    for nombre, m in REGISTRO.items():
        res, _ = ejecutar_alice(nombre, MSG)
        i, met = m["info"], res.get("metricas", {})
        filas.append({
            "Categoría": m["categoria"], "Apartado": m["apartado"], "Mecanismo": nombre,
            "Entradas": i["entradas"], "Componentes": i["componentes"],
            "Secreto": i["secreto"], "Público": i["publico"], "Salidas": i["salidas"],
            "Propiedad": res["propiedad"], "Condiciones de uso": res["condiciones"],
            "Consecuencia de uso incorrecto": i["mal_uso"],
            "Tiempo (ms)": str(met.get("tiempo_ms", "-")), "Memoria (KB, tracemalloc)": str(met.get("memoria_kb", "-")),
            "Bytes entrada": str(met.get("bytes_entrada", "-")), "Bytes salida": str(met.get("bytes_salida", "-")),
        })
    return filas


def a_markdown(filas: list) -> str:
    cols = list(filas[0].keys())
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for f in filas:
        out.append("| " + " | ".join(str(f[c]).replace("|", "/").replace("\n", " ") for c in cols) + " |")
    out.append("\n*Memoria medida con tracemalloc: solo ve asignaciones de Python; no incluye la memoria "
               "de bibliotecas nativas (OpenSSL), por eso Scrypt (~16 MiB reales) aparece casi en 0 KB.*")
    return "\n".join(out)


if __name__ == "__main__":
    md = a_markdown(construir_tabla())
    with open("tabla_mecanismos.md", "w", encoding="utf-8") as f:
        f.write(md)
    print("Generado tabla_mecanismos.md")
