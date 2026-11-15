import requests
import os
from zkp import Session

# Configuración del Comisionador
DEVICE_URL = os.getenv("DEVICE_URL", "http://127.0.0.1:5001")
COMMISSIONER_ID = os.getenv("COMMISSIONER_ID", "Celular_Admin")


class Commissioner:
    def __init__(self, user_id=COMMISSIONER_ID, device_url=DEVICE_URL):
        self.device_url = device_url
        # Crea la sesión del celular en memoria 
        self.session = Session(user_id=user_id)

    def discover(self):
        #Pregunta por el info del dispositivo
        try:
            res = requests.get(f"{self.device_url}/info", timeout=5)
            if res.status_code == 200:
                return res.json()
            return None
        except requests.exceptions.ConnectionError:
            return None

    def commission(self, proof=None, user_id=None, basic_mode=False):

        target_user = user_id if user_id is not None else self.session.user_id

        if proof is None:
            if basic_mode:
                proof = self.session.create_proof_basic()
            else:
                proof = self.session.create_proof()

        payload = {
            "user_id": target_user,
            "public_key": self.session.get_public_key_hex(),
            "proof": proof,
        }

        endpoint = "/commission-basic" if basic_mode else "/commission"
        res = requests.post(f"{self.device_url}{endpoint}", json=payload, timeout=5)
        return res.status_code, res.json()
