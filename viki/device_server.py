from flask import Flask, request, jsonify
from zkp import Session
import os

# Puerto y configuración del dispositivo
PORT = int(os.getenv("DEVICE_PORT", 5001))
DEVICE_ID = os.getenv("DEVICE_ID", "Thread_SmartBulb_01")


def create_app():
    app = Flask(__name__)

    @app.route("/info", methods=["GET"])
    def get_info():

        #Endpoint de descubrimiento
        #El celular descubre el dispositivo y obtiene su identidad y clave pública. 
        return jsonify({
            "status": "ready_for_commissioning",
            "device_id": session.user_id,
            "public_key": session.get_public_key_hex(),
            "protocol": "Thread Commissioning (RFC 8235 ZKP)",
        })

    @app.route("/commission", methods=["POST"])
    def commission():
        
        # Endpoint estándar (RFC 8235)
        # Se recibe la prueba ZKP del celular.
        # Se verifica que el celular conozca su secreto Y que la prueba pertenezca a su UserID.
        # Si es válida, responde con la prueba ZKP del propio dispositivo (Autenticación Mutua).
        
        data = request.get_json()

        # Validación de campos requeridos
        if not isinstance(data, dict):
            return jsonify({"error": "Formato JSON inválido"}), 400

        required_fields = ["user_id", "public_key", "proof"]
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Faltan campos requeridos: user_id, public_key, proof"}), 400

        proof = data.get("proof")
        if not isinstance(proof, dict) or "commitment" not in proof or "response" not in proof:
            return jsonify({"error": "Estructura de proof inválida (debe contener commitment y response)"}), 400

        user_id = data["user_id"]
        public_key = data["public_key"]

        print(f"\n[DISPOSITIVO] Recibida solicitud de comisionamiento de: '{user_id}'")
        print(f"[DISPOSITIVO] Clave pública recibida: {public_key[:16]}...{public_key[-16:]}")

        # Verificación criptográfica con el estándar RFC 8235
        is_valid = session.verify_proof(
            other_user_id=user_id,
            other_public_key_hex=public_key,
            proof=proof,
        )

        if not is_valid:
            print(f"[DISPOSITIVO] RECHAZO: Prueba ZKP inválida o UserID no coincide.")
            return jsonify({
                "status": "rejected",
                "error": "Verificación ZKP fallida (prueba alterada o suplantación de UserID).",
            }), 401

        print(f"[DISPOSITIVO] APROBADO: Prueba ZKP legítima verificada.")

        # Generar la prueba del dispositivo hacia el celular (Autenticación Mutua)
        device_proof = session.create_proof()

        return jsonify({
            "status": "commissioned",
            "message": f"Dispositivo '{session.user_id}' comisionado exitosamente en la red Thread.",
            "device_id": session.user_id,
            "device_public_key": session.get_public_key_hex(),
            "device_proof": device_proof,
        }), 200



    @app.route("/commission-basic", methods=["POST"])
    def commission_basic():
        
        #Endpoint vulnerable (Versión Básica c = H(A)):

        data = request.get_json()
        if not isinstance(data, dict) or "public_key" not in data or "proof" not in data:
            return jsonify({"error": "Faltan campos requeridos"}), 400

        public_key = data["public_key"]
        proof = data["proof"]
        claimed_user = data.get("user_id", "Desconocido")

        print(f"\n[DISPOSITIVO (BÁSICO)] Solicitud en versión básica de: '{claimed_user}'")

        # La versión básica solo valida c = H(A), ¡sin comprobar si pertenece al claimed_user!
        is_valid = session.verify_proof_basic(public_key, proof)

        if is_valid:
            print(f"[DISPOSITIVO (BÁSICO)] ! ACEPTADO: La versión básica no detecta si el UserID fue suplantado.")
            return jsonify({
                "status": "commissioned_insecure",
                "warning": "VULNERABILIDAD: Aceptado por versión básica sin validar UserID.",
                "user_id": claimed_user,
            }), 200

        return jsonify({"status": "rejected", "error": "Prueba básica inválida"}), 401

    return app


if __name__ == "__main__":
    #Genera la sesión al entrar al servidor.
    session = Session(user_id=DEVICE_ID)

    print(f"Dispositivo Thread iniciado: {session.user_id}")
    print(f"Servidor escuchando en: http://127.0.0.1:{PORT}")

    app = create_app()
    app.run(host="127.0.0.1", port=PORT, debug=False)
