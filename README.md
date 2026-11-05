# Laboratorio educativo de criptografía: Alice, Bob y Eve

Aplicación educativa (Python + Streamlit) para **comprender y comparar** mecanismos criptográficos
sin llaves, simétricos y asimétricos. Cada mecanismo se ejecuta con tres personajes:

- **Alice** (emisor): introduce un mensaje, elige el mecanismo y ejecuta la operación.
- **Eve** (observador/atacante simulado): ve **solo** los datos públicos del canal y puede modificar, sustituir o reenviar.
- **Bob** (receptor): verifica o descifra y explica si **acepta o rechaza**.

> Todos los datos son inventados para la práctica. **Eve nunca recibe llaves secretas o privadas.**
> La filtración de llaves es un escenario separado y explícito (menú "Filtración de llaves").

## Requisitos
- Python 3.10 o superior (probado en 3.13)
- Bibliotecas: `cryptography` y `streamlit` (ver `requirements.txt`)

## Instalación (Windows / PowerShell)
```powershell
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
```
En Mac/Linux: `source venv/bin/activate`.

## Ejecución
```powershell
python -m streamlit run app.py
```
Se abre en `http://localhost:8501`. Para detener: `Ctrl+C` en la terminal.

## Menú principal
| Apartado | Mecanismos |
|---|---|
| Cifrados sin uso de llaves | Funciones hash (SHA-256, SHA3-256); construcción esponja y salida extensible (SHAKE128/256) |
| Cifrado simétrico | AES-CBC y AES-GCM; ChaCha20 y AES-CTR; HMAC y CMAC; KDF (Scrypt, PBKDF2) |
| Cifrado asimétrico | RSA-OAEP; firmas Ed25519 y RSA-PSS; X25519 (con y sin firmas); PKI con certificados X.509 |
| Laboratorio de escenarios | Los 9 escenarios de manipulación y ataque |
| Filtración de llaves | Escenario aparte donde Eve SÍ tiene la llave |
| Tabla de mecanismos | Entradas, componentes, propiedades, recursos y condiciones de uso |

Para cada mecanismo la interfaz responde: ¿qué protección da?, ¿qué componentes necesita?, ¿qué recursos consume?
y ¿qué pasa si se usa mal?

## Estructura
```
cripto-lab/
├── app.py                      Interfaz (Alice, Bob, Eve, menú, laboratorio)
├── metricas.py                 Medición de tiempo y memoria
├── tabla.py                    Genera tabla_mecanismos.md
├── mecanismos/                 hashes, esponja, bloques, flujo, mac, kdf, rsa_cifrado,
│                               firmas, intercambio, pki, registro (conecta todo con la interfaz)
├── ataques/                    diccionario, comparar_kdf, manipulacion, mac_y_repeticion,
│                               escenarios_asimetricos, filtracion
├── test_*.py                   Pruebas por consola (evidencias)
└── tabla_mecanismos.md         Tabla generada
```

## Pruebas por consola (evidencias)
```powershell
python test_hashes.py        # hash correcto y modificación detectada
python test_diccionario.py   # ataque de diccionario (débil vs fuerte)
python test_kdf.py           # SHA-256 vs Scrypt: intentos por segundo
python test_cifrado.py       # CBC/GCM/ChaCha20/CTR y alteración de mensajes
python test_mac.py           # HMAC/CMAC y repetición de mensajes
python test_asimetricos.py   # RSA, firmas, MITM y PKI
python test_registro.py      # recorre TODOS los mecanismos y todas las acciones de Eve
python tabla.py              # genera tabla_mecanismos.md
```

## Herramientas externas de ataque (opcional, solo con datos de práctica)
- **Hashcat**: `hashcat -m 1400 -a 0 hash.txt diccionario.txt` (SHA-256, ataque de diccionario).
- **John the Ripper**: `john --format=Raw-SHA256 --wordlist=diccionario.txt hash.txt`.
- Requieren descargar la herramienta aparte; úsalas únicamente con los hashes de práctica del proyecto.

## Limitaciones
- La memoria se mide con `tracemalloc`, que **solo ve asignaciones de Python**; no incluye la memoria de
  bibliotecas nativas (OpenSSL). Ejemplo: Scrypt usa ~16 MiB reales y aparece casi en 0 KB.
- Es un proyecto educativo: no usar este código como sistema de producción.
