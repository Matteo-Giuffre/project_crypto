from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# La tua chiave pubblica PEM (come stringa)
public_key_pem = b"""
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmxCdxJb8Gai/Hko5DbOCChNHqKll
arsJWlTP8Y4UupUCQmeo+cTqyvL1+3WNQHcWGzfgAlK9SzkV1PbTvi581g==
-----END PUBLIC KEY-----
"""

def load_public_key(pem_data: bytes):
    return serialization.load_pem_public_key(pem_data)

def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def main():
    # Carica chiave pubblica
    pub_key = load_public_key(public_key_pem)

    # Leggi documento originale
    with open("tabelle_db.txt", "rb") as f:
        document = f.read()

    # Leggi firma digitale
    with open("tabelle_db.sig", "rb") as f:
        signature = f.read()

    # Verifica firma
    if verify_signature(pub_key, document, signature):
        print("Firma valida!")
    else:
        print("Firma NON valida!")

if __name__ == "__main__":
    main()
