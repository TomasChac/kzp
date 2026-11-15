# Laboratorio 7: Zero-Knowledge Proofs (ZKP) en Casas Inteligentes
**TEL252 - Criptografía y Seguridad en la Información**  
**Aplicación:** Comisionamiento seguro en redes Thread (Smart Homes)  
**Estándar:** RFC 8235 (*Schnorr Non-interactive Zero-Knowledge Proof*)  
**Curva:** NIST P-256 (`NIST256p`)

---

## 1. Arquitectura del Sistema
El sistema implementa la autenticación mutua de conocimiento cero para agregar un nuevo dispositivo inteligente (ej. Foco/Sensor) a la red de una casa inteligente sin revelar secretos y vinculando las identidades de ambos actores para evitar suplantaciones (*Credential Forwarding / Replay Attacks*).

- **Proceso 1 (`device_server.py`)**: Representa al dispositivo IoT (Foco Thread) corriendo un servidor Flask en `http://127.0.0.1:5001`.
- **Proceso 2 (`commissioner.py` / `run_demo.py`)**: Representa la aplicación móvil (Celular comisionador) con un menú interactivo en terminal para ejecutar las pruebas.

---

## 2. Instrucciones para la Demo en Vivo

Abra dos terminales en la carpeta `Lab7`:

### Terminal 1: Iniciar el Dispositivo IoT (Servidor)
```powershell
python device_server.py
```
*(Opcional: puede cambiar la identidad del dispositivo definiendo `$env:DEVICE_ID="Sensor_Cocina"`)*.

### Terminal 2: Iniciar la Demo Interactiva (Celular)
```powershell
python run_demo.py
```

En la Terminal 2 aparecerá el menú interactivo para la presentación:
* **Opción [1]**: Descubrimiento del dispositivo en la red (`GET /info`).
* **Opción [2] (Caso 1)**: Comisionamiento exitoso con RFC 8235 y autenticación mutua legítima (`HTTP 200 OK`).
* **Opción [3] (Caso 2)**: Demostración de rechazo por alteración matemática de la prueba (`HTTP 401 Unauthorized`).
* **Opción [4] (Caso 3)**: Demostración de rechazo ante intento de suplantación de identidad / reenvío de credenciales en RFC 8235 (`HTTP 401 Unauthorized`).
* **Opción [5] (Caso 4)**: Demostración de vulnerabilidad en la versión básica ingenua $c = H(A)$, donde el atacante logra entrar (`HTTP 200 OK`).
* **Opción [6]**: Ejecución de todos los casos en secuencia automática.

---

## 3. Evidencias de las Bibliotecas para Producción (Pauta Ítem 6)

1. **`cryptography` (Python Cryptographic Authority - PyCA)**:
   - **Backend**: OpenSSL 3.x y extensiones en lenguaje Rust.
   - **Certificación FIPS**: OpenSSL cuenta con validación **FIPS 140-2 / FIPS 140-3** bajo el programa **CMVP/CAVP** del NIST.
   - **Auditorías**: Auditada por firmas globales líderes como **Trail of Bits** y **Cure53**.
   - **Uso en producción**: Es la biblioteca que protege a `pip`, `AWS CLI`, `Google Cloud SDK` y `pyOpenSSL`.
   - **Tiempo constante**: Operaciones de hashing y curvas ejecutadas en tiempo constante, mitigando ataques de canal lateral (*timing attacks*).

2. **`ecdsa`**:
   - Biblioteca madura para aritmética sobre curvas elípticas estandarizadas (NIST P-256).
   - Utilizada ampliamente en proyectos de infraestructura criptográfica como `python-jose` (manejo de JWTs en producción).

3. **`secrets` (Módulo estándar de Python)**:
   - Generación de claves privadas y nonces efímeros mediante el CSPRNG del sistema operativo (`/dev/urandom` / `BCryptGenRandom`).

---

## 4. Límites de la Confianza (Pauta Ítem 5)

* **Lo que la criptografía garantiza**: La ZKP (RFC 8235) demuestra matemáticamente que quien emite la prueba conoce la clave privada $x$ de la clave pública $Y$, y que la prueba fue emitida específicamente para ese `user_id`.
* **Dónde termina la criptografía**: La ZKP no puede determinar si la clave pública $Y$ corresponde al foco físico real que el usuario compró en la tienda, o a un dispositivo espía en la calle.
* **El ancla de confianza física (Thread / J-PAKE / RFC 8236)**: La confianza se ancla en el mundo físico a través del **código QR o PIN de 8 dígitos impreso en la caja o etiqueta del foco**. Ambos actores combinan la ZKP con este secreto compartido fuera de banda, confiando en la seguridad física del hogar y en la cadena de suministro del fabricante.

