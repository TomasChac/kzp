#Estándar: Protocolo no interactivo de Schnorr (RFC8235)
#Curva: NIST256p (P-256)

from ecdsa import SigningKey, VerifyingKey, NIST256p
from secrets import randbelow
import hashlib


class Session:
    def __init__(self, user_id: str = "Device"):
        # Identificador del actor (leído desde configuración o parámetro)
        self.user_id = user_id

        # Parámetros de la curva elíptica NIST P-256
        self.curve = NIST256p
        self.n = NIST256p.order
        self.G = NIST256p.generator

        # Llave privada x (SigningKey) y llave pública Y = x * G (VerifyingKey)
        # Generadas de forma criptográficamente segura en memoria
        self.sk = SigningKey.generate(curve=self.curve)
        self.vk = self.sk.verifying_key
        self.x = self.sk.privkey.secret_multiplier

    def get_public_key_hex(self) -> str:
        #Retorna la llave pública Y en formato hexadecimal.
        return self.vk.to_string().hex()

    # VERSIÓN ESTANDAR RFC8235
    def create_proof(self) -> dict:
    
        #Prueba no interactiva de Schnorr según el estándar RFC 8235
    
        # 1. Nonce efímero y compromiso A
        v = randbelow(self.n - 1) + 1
        point_A = v * self.G
        vk_A = VerifyingKey.from_public_point(point_A, curve=self.curve)
        A_hex = vk_A.to_string().hex()

        # 2. Desafío RFC 8235
        g_bytes = VerifyingKey.from_public_point(self.G, curve=self.curve).to_string()
        y_bytes = self.vk.to_string()
        a_bytes = vk_A.to_string()
        user_bytes = self.user_id.encode("utf-8")

        transcript = g_bytes + y_bytes + a_bytes + user_bytes
        c = int.from_bytes(hashlib.sha256(transcript).digest(), "big") % self.n

        # 3. Respuesta escalar
        r = (v - c * self.x) % self.n

        return {
            "commitment": A_hex,
            "response": hex(r),
        }

    def verify_proof(self, other_user_id: str, other_public_key_hex: str, proof: dict) -> bool:

        #Verificación de una prueba RFC 8235 emitida por otra parte

        try:
            # 1. Reconstrucción de puntos con validación de pertenencia a la curva
            other_vk = VerifyingKey.from_string(bytes.fromhex(other_public_key_hex), curve=self.curve)
            point_Y = other_vk.pubkey.point

            vk_A = VerifyingKey.from_string(bytes.fromhex(proof["commitment"]), curve=self.curve)
            point_A = vk_A.pubkey.point

            r = int(proof["response"], 16)
        except Exception:
            return False

        # 2. Recalcular el desafío con el UserID que el otro actor declara ser
        g_bytes = VerifyingKey.from_public_point(self.G, curve=self.curve).to_string()
        y_bytes = other_vk.to_string()
        a_bytes = vk_A.to_string()
        user_bytes = other_user_id.encode("utf-8")

        transcript = g_bytes + y_bytes + a_bytes + user_bytes
        c = int.from_bytes(hashlib.sha256(transcript).digest(), "big") % self.n

        # 3. Ecuación de verificación: r*G + c*Y == A
        reconstructed_A = r * self.G + c * point_Y
        return reconstructed_A == point_A


    # VERSIÓN BÁSICA (VULNERABLE)

    def create_proof_basic(self) -> dict:

        #Versión básica:
        #El desafío se calcula solo sobre el compromiso A.
        
        v = randbelow(self.n - 1) + 1
        point_A = v * self.G
        vk_A = VerifyingKey.from_public_point(point_A, curve=self.curve)
        A_hex = vk_A.to_string().hex()

        # Desafío básico c = H(A)
        c = int.from_bytes(hashlib.sha256(vk_A.to_string()).digest(), "big") % self.n
        r = (v - c * self.x) % self.n

        return {
            "commitment": A_hex,
            "response": hex(r),
        }

    def verify_proof_basic(self, other_public_key_hex: str, proof: dict) -> bool:

        #Verificación de la versión básica:
        #Comprueba r*G + c*Y == A, pero no se verifica quién es el emisor de la prueba.
    
        try:
            other_vk = VerifyingKey.from_string(bytes.fromhex(other_public_key_hex), curve=self.curve)
            point_Y = other_vk.pubkey.point

            vk_A = VerifyingKey.from_string(bytes.fromhex(proof["commitment"]), curve=self.curve)
            point_A = vk_A.pubkey.point

            r = int(proof["response"], 16)
        except Exception:
            return False

        c = int.from_bytes(hashlib.sha256(vk_A.to_string()).digest(), "big") % self.n
        reconstructed_A = r * self.G + c * point_Y
        return reconstructed_A == point_A