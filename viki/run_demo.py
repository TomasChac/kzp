import time
from commissioner import Commissioner


def test_discover(comm):
    print("\n" + "=" * 65)
    print("  [DEMO] DESCUBRIMIENTO DEL DISPOSITIVO (GET /info)")
    print("=" * 65)
    data = comm.discover()
    if data:
        print("Dispositivo encontrado:")
        print(f"          - ID: {data.get('device_id')}")
        print(f"          - Clave pública (Y): {data.get('public_key')[:24]}...")
        print(f"          - Estado: {data.get('status')}")
    else:
        print(f"No se pudo conectar a {comm.device_url}.")
        print("          Asegúrese de ejecutar 'device_server.py' en la otra terminal.")


def test_case_1_happy_path(comm):
    print("\n" + "=" * 65)
    print("  [DEMO] CASO 1: COMISIONAMIENTO EXITOSO (RFC 8235 - AUTENTICACIÓN MUTUA)")
    print("=" * 65)

    print(f"1. Generando prueba ZKP RFC 8235 para '{comm.session.user_id}'...")
    status, data = comm.commission()

    print(f"2. Respuesta del dispositivo: HTTP {status}")
    if status == 200:
        print(f"El dispositivo aceptó la prueba del celular.")
        print(f"Mensaje: {data.get('message')}")

        # Autenticación mutua: celular verifica la prueba devuelta por el dispositivo
        print(f"\n3. Verificando prueba devuelta por '{data.get('device_id')}'...")
        is_device_valid = comm.session.verify_proof(
            other_user_id=data.get("device_id"),
            other_public_key_hex=data.get("device_public_key"),
            proof=data.get("device_proof"),
        )

        if is_device_valid:
            print("Autenticación mutua completada exitosamente.")
            print("Ambas partes demostraron conocer sus secretos sin revelarlos.")
        else:
            print("Fallo: La prueba devuelta por el dispositivo es inválida.")
    else:
        print(f"Error: {data.get('error')}")


def test_case_2_tampered_proof(comm):
    print("\n" + "=" * 65)
    print("  [DEMO] CASO 2: RECHAZO POR PRUEBA ALTERADA (TAMPERED PROOF)")
    print("=" * 65)

    print("1. Generando prueba legítima y alterando 1 bit de la respuesta 'r'...")
    legit_proof = comm.session.create_proof()

    # Modificar un bit en la respuesta escalar r (XOR con 0x01)
    tampered_r = hex(int(legit_proof["response"], 16) ^ 0x01)
    corrupt_proof = {
        "commitment": legit_proof["commitment"],
        "response": tampered_r,
    }

    print("2. Enviando prueba corrupta al dispositivo...")
    status, data = comm.commission(proof=corrupt_proof)

    print(f"3. Código HTTP recibido: {status}")
    print(f"Mensaje del servidor: {data}")

    if status == 401:
        print("Rechazo por parte del servidor: La API detectó la corrupción matemática de la prueba.")
    else:
        print("Error: El servidor aceptó la prueba corrupta.")


def test_case_3_impersonation_rfc8235(comm):
    print("\n" + "=" * 65)
    print("  [DEMO] CASO 3: RECHAZO POR SUPLANTACIÓN DE IDENTIDAD (RFC 8235)")
    print("=" * 65)

    print(f"1. '{comm.session.user_id}' genera una prueba legítima...")
    legit_proof = comm.session.create_proof()

    print("2. Un atacante intercepta la prueba y la envía como 'Atacante_Mallory'...")
    status, data = comm.commission(proof=legit_proof, user_id="Atacante_Mallory")

    print(f"3. Código HTTP recibido: {status}")
    print(f"Mensaje del servidor: {data}")

    if status == 401:
        print("Rechazo por parte del servidor: RFC 8235 es inmune a la suplantación.")
    else:
        print("Error: El servidor aceptó la suplantación.")


def test_case_4_vulnerability_basic(comm):
    print("\n" + "=" * 65)
    print("  [DEMO] CASO 4: DEMOSTRACIÓN DE VULNERABILIDAD EN VERSIÓN BÁSICA (c = H(A))")
    print("=" * 65)

    print("1. Generando prueba con la versión básica (c = H(A))...")
    basic_proof = comm.session.create_proof_basic()

    print("2. El atacante presenta la prueba bajo el nombre 'Atacante_Mallory'...")
    status, data = comm.commission(proof=basic_proof, user_id="Atacante_Mallory", basic_mode=True)

    print(f"3. Código HTTP recibido: {status}")
    print(f"Mensaje del servidor: {data}")

    if status == 200:
        print("\nVULNERABILIDAD EXPLOTADA:")
    else:
        print("La prueba básica no fue aceptada.")


def main():
    comm = Commissioner()

    while True:
        print("\n" + "=" * 65)
        print("  DEMO EN VIVO: COMISIONAMIENTO THREAD CON ZERO-KNOWLEDGE PROOFS")
        print("=" * 65)
        print(f"  Actor: {comm.session.user_id} | Servidor: {comm.device_url}")
        print("  " + "-" * 61)
        print("  [1] Descubrir dispositivo en la red (GET /info)")
        print("  [2] Caso 1: Comisionamiento exitoso (RFC 8235 - Autenticación Mutua)")
        print("  [3] Caso 2: Rechazo por prueba alterada (Tampered Proof)")
        print("  [4] Caso 3: Rechazo por suplantación de UserID (RFC 8235)")
        print("  [5] Caso 4: Demostración de vulnerabilidad básica (Weak Fiat-Shamir)")
        print("  [6] Ejecutar todos los casos en secuencia")
        print("=" * 65)

        choice = input("Seleccione una opción [1-6]: ").strip()

        if choice == "1":
            test_discover(comm)
        elif choice == "2":
            test_case_1_happy_path(comm)
        elif choice == "3":
            test_case_2_tampered_proof(comm)
        elif choice == "4":
            test_case_3_impersonation_rfc8235(comm)
        elif choice == "5":
            test_case_4_vulnerability_basic(comm)
        elif choice == "6":
            print("\n>>> EJECUTANDO TODOS LOS CASOS EN SECUENCIA...")
            test_discover(comm)
            time.sleep(1)
            test_case_1_happy_path(comm)
            time.sleep(1)
            test_case_2_tampered_proof(comm)
            time.sleep(1)
            test_case_3_impersonation_rfc8235(comm)
            time.sleep(1)
            test_case_4_vulnerability_basic(comm)
        else:
            print("Opción inválida. Ingrese un número entre 0 y 6.")

        input("\nPresione Enter para continuar...")


if __name__ == "__main__":
    main()
