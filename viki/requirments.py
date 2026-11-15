"""
requirments.py / requirements.txt
Dependencias del proyecto TEL252 - Laboratorio 7 (ZKP)
"""

requirements = [
    "flask>=3.0.0",
    "ecdsa>=0.19.0",
    "cryptography>=41.0.0",
    "requests>=2.31.0",
]

if __name__ == "__main__":
    for req in requirements:
        print(req)
