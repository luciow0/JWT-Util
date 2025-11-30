# JWT Swiss Army Knife (`jwtUtil.py`)

Una herramienta de línea de comandos (CLI) robusta y modular para **Pentesting de JWT** y **Criptografía**. Diseñada para facilitar la manipulación de tokens, ataques de confusión de claves y conversión de formatos criptográficos.

## 🚀 Módulos y Funcionalidades

### 1. Manipulación de JWT (`process`)
El núcleo de la herramienta para manipular tokens. Permite decodificar, modificar (tampering) y volver a firmar tokens.

*   **Decodificación**:
    *   **Modo Inseguro (`--no-verify`)**: Inspecciona headers y payload sin validar la firma.
    *   **Modo Seguro (`--verify-key`)**: Verifica la firma contra una clave pública (PEM) o secreto (HMAC).
*   **Manipulación (Tampering)**:
    *   **Payload (`--set-claim`)**: Inyecta o modifica valores en el cuerpo del token (detecta tipos de datos automáticamente).
    *   **Headers (`--set-header`)**: Inyecta o modifica cabeceras. **Soporta inyección de objetos JSON** (crítico para ataques avanzados como Key Confusion).
*   **Firma (Signing)**:
    *   **Algoritmos**: `HS256` (HMAC), `RS256` (RSA), `none` (Sin firma).
    *   **Claves (`--sign-key`)**: Acepta archivos PEM o strings directos como secretos.

### 2. Conversión de Claves (`key-convert`)
Tu navaja suiza para transformar formatos criptográficos.

*   **Formatos de Entrada**: Detecta automáticamente JWK (JSON) o PEM.
*   **Formatos de Salida (`--key-format`)**:
    *   `pkcs8`: Estándar para claves privadas.
    *   `pkcs1`: Formato tradicional RSA (`BEGIN RSA...`).
    *   `x509`: Estándar para claves públicas (`BEGIN PUBLIC KEY...`).
    *   `oct`: **Generación de JWK Simétrico**. Convierte cualquier input (ej. una clave pública PEM) en un JWK de tipo `oct`, usando el contenido del archivo como la clave `k`. (Vital para Key Confusion).
*   **Formato de Texto**:
    *   `--line-ending`: Control total sobre saltos de línea (`linux`, `windows`, `none`).
    *   `--no-eof`: Opción para eliminar el salto de línea final.

### 3. Utilidades (`b64`)
Herramientas auxiliares.
*   **Base64**: Codificación y decodificación estándar.
*   **URL-Safe (`--url`)**: Variante usada en JWTs (reemplaza `+` y `/` por `-` y `_`).

---

## 📖 Guía de Uso y Comandos

### 1. `process` (Manipulación de JWT)
`python jwtUtil.py process <TOKEN> [OPCIONES]`

| Argumento | Descripción |
| :--- | :--- |
| **`token`** | El string del JWT a procesar (Obligatorio). |
| `--no-verify` | Decodifica el token sin verificar la firma (Modo inseguro). |
| `--verify-key <KEY>` | Verifica la firma usando esta clave (Ruta a archivo PEM o string secreto). |
| `--set-claim <KEY=VAL>` | Modifica o añade un claim al payload. Puede usarse múltiples veces. |
| `--set-header <KEY=VAL>` | Modifica o añade un header. Soporta valores JSON (ej: `jwk='{...}'`). |
| `--alg <ALG>` | Algoritmo para resignar (`HS256`, `RS256`, `none`). |
| `--sign-key <KEY>` | Clave para resignar (Ruta a archivo PEM o string secreto). |
| `--output <FMT>` | Formato de salida: `json` (payload decodificado) o `jwt` (token firmado). |

**Ejemplos:**

*   **Ver contenido (Inseguro):**
    ```bash
    python jwtUtil.py process eyJhbGci... --no-verify
    ```
*   **Modificar Payload y Resignar (HMAC):**
    ```bash
    python jwtUtil.py process eyJhbGci... --no-verify --set-claim role=admin --alg HS256 --sign-key "123456"
    ```
*   **Ataque Key Confusion (Inyección de Header JSON):**
    ```bash
    python jwtUtil.py process eyJhbGci... --no-verify --set-header jwk='{"kty":"oct","k":"..."}' --alg HS256 --sign-key public.pem
    ```

### 2. `key-convert` (Conversión de Claves)
`python jwtUtil.py key-convert <INPUT> [OPCIONES]`

| Argumento | Descripción |
| :--- | :--- |
| **`input`** | Ruta al archivo o string con la clave (JWK o PEM). |
| `--out <FILE>` | Ruta del archivo de salida (Opcional). |
| `--key-format <FMT>` | Formato de salida: `pkcs8`, `pkcs1`, `x509`, `oct`. |
| `--line-ending <FMT>` | Saltos de línea: `linux` (`\n`), `windows` (`\r\n`), `none` (una línea). |
| `--no-eof` | No agrega un salto de línea al final del archivo/output. |

**Ejemplos:**

*   **JWK a PEM (Estándar):**
    ```bash
    python jwtUtil.py key-convert jwk.json --out clave.pem
    ```
*   **PEM a JWK Simétrico (`oct`) - Para Key Confusion:**
    ```bash
    python jwtUtil.py key-convert public.pem --key-format oct
    ```
*   **One-Liner para exploits (Sin saltos de línea):**
    ```bash
    python jwtUtil.py key-convert jwk.json --line-ending none --no-eof
    ```

### 3. `b64` (Herramienta Base64)
`python jwtUtil.py b64 <INPUT> [OPCIONES]`

| Argumento | Descripción |
| :--- | :--- |
| **`input`** | El texto o string a procesar. |
| `-d`, `--decode` | Activa el modo decodificación (por defecto codifica). |
| `--url` | Usa el alfabeto URL-Safe. |

**Ejemplo:**
```bash
python jwtUtil.py b64 "eyJhbGciOiJIUzI1NiJ9" -d --url
```
