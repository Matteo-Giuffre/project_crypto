import os
import time
import socket
import bcrypt
import json
import base64

import mysql.connector

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

passphrase = os.getenv("PRIVATE_KEY_PASSPHRASE").encode()

SERVER_ADDR = ('localhost', 12345)

nonce_cache = {}

DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': 'crypto',
    'database': 'crypto_project',
    'port': 3306,
    'ssl_disabled': False 
}

def open_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"Connection error: {err}")
        return None

def send_json(conn, data_dict, aesgcm):

    plaintext = json.dumps(data_dict).encode()
    nonce_aes = os.urandom(12)  # AES-GCM nonce
    ciphertext = aesgcm.encrypt(nonce_aes, plaintext, None)
    try:
        # Invia nonce_AES + ciphertext con lunghezze
        conn.sendall(len(nonce_aes).to_bytes(2, 'big') + nonce_aes)
        conn.sendall(len(ciphertext).to_bytes(4, 'big') + ciphertext)
        return True
    except Exception as e:
        print(f"Error in send_json: {e}")
        return False

def recv_json(conn, aesgcm):
    try:
        len_nonce = int.from_bytes(conn.recv(2), 'big')
        nonce = conn.recv(len_nonce)

        len_cipher = int.from_bytes(conn.recv(4), 'big')
        ciphertext = conn.recv(len_cipher)

        # Decrittazione AES-GCM
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # Parsing JSON
        data = json.loads(plaintext.decode())
        return data

    except Exception as e:
        print(f"Error in recv_json: {e}")
        return False

def is_nonce_valid(nonce):
    now = time.time()
    # Pulisci la cache
    expiration = 60 * 30  # 30 minuti, tempo di validità
    expired = [n for n, ts in nonce_cache.items() if now - ts > expiration]
    for n in expired:
        del nonce_cache[n]

    # Controlla se la nonce già presente
    if nonce in nonce_cache:
        return False  # replay nonce
    else:
        nonce_cache[nonce] = now
        return True

def session_key_validity(session_key_creation_time):
    # validità di 30 minuti
    validity_period = 60 * 30

    if (time.time() - session_key_creation_time) >= validity_period:
        print("Error: invalid session key.")
        return False
    
    return True

def check_credentials(username: str, password: str) -> tuple[bool, bool]:

    db_conn = open_db_connection()
    if db_conn is None:
        print("Error connecting db")
        return (None, None)

    try:
        cursor = db_conn.cursor()
        cursor.execute("SELECT password, is_new FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        if not result:
            print("User not found.")
            return (False,False)

        stored_hash = result[0].encode()  # il valore dal DB è str, serve bytes
        #verifico se le credenziali sono corrette, ma anche se l'utente è new(quindi deve cambiare pwd) 
        # restituendo una tupla (check_credentials(T or F), is_new(T or F))
        if not bcrypt.checkpw(password.encode(), stored_hash):
            print("Invalid credentials")
            return (False, False)#credenziali errate
        
        is_new = bool(result[1])  # is_new è un int (0 o 1), lo convertiamo in bool
        return (True, is_new)
            
    except mysql.connector.Error as err:
        print(f"Query error: {err}")
        return (None, None)
    finally:
        cursor.close()
        db_conn.close()

def update_user_password(username: str, nuova_password: str) -> bool:

    db_conn = open_db_connection()
    if db_conn is None:
        print("Error connection to db (update pwd).")
        return False

    try:
        # Hash della nuova password
        hashed_pwd = bcrypt.hashpw(nuova_password.encode(), bcrypt.gensalt())

        cursor = db_conn.cursor()
        query = """
            UPDATE users
            SET password = %s, is_new = 0
            WHERE username = %s
        """
        cursor.execute(query, (hashed_pwd.decode(), username))
        db_conn.commit()
        return True

    except mysql.connector.Error as err:
        print(f"Query error: {err}")
        return False

    finally:
        cursor.close()
        db_conn.close()

def handle_handshake(conn):
    
    #1. Ricevo epkC, nonceC
    try:
        len_epkC = int.from_bytes(conn.recv(2), 'big')
        epkC = conn.recv(len_epkC)
        len_nonceC = int.from_bytes(conn.recv(2), 'big')
        nonceC = conn.recv(len_nonceC)
    except Exception as e:
        print("Error in data receiving:", e)
        return False, False

    #Verifica la nonce
    if not is_nonce_valid(nonceC):
        print("Handshake error: nonceC is invalid!")
        return False , False

    # 2. Genero la ECDHE keypair ephimeral_secret_key_Server e ephimeral_public_key_Server
    eskS = ec.generate_private_key(ec.SECP256R1())
    epkS = eskS.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)

    #Carica la chiave privata DSS per firmare
    with open("dss_private.pem", "rb") as f:
        dss_priv = load_pem_private_key(f.read(), password=None)

    # Firmo epkS || epkC || nonceC || nonceS
    nonceS = os.urandom(16)
    signed_data = epkS + epkC + nonceC + nonceS

    signature = dss_priv.sign(
        signed_data,
        ec.ECDSA(hashes.SHA256())
    )

    # 3. Invio [epkS, nonceS, Signature]
    try:
        conn.sendall(len(epkS).to_bytes(2, 'big') + epkS)
        conn.sendall(len(nonceS).to_bytes(2, 'big') + nonceS)
        conn.sendall(len(signature).to_bytes(2, 'big') + signature)
    except Exception as e:
        print("Error in data sending:", e)
        return False, False

    # 4. Genero session key con ECDH
    client_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epkC)
    shared_secret = eskS.exchange(ec.ECDH(), client_pub_key)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonceC + nonceS,
        info=b'handshake data',
    ).derive(shared_secret)
    session_key_creation_time = time.time()
    return session_key, session_key_creation_time

def handle_login(conn, sk, sk_ct):

    # Una volta stabilito il canale di comunicazione sicuro il server
    # autentica il client mediante la sua password (login)
    # Ricevo E(sessionkey, "username || pwd || nonceC")
    
    #Verifico la validità della session key
    if not(session_key_validity(sk_ct)):
        return False

    aesgcm = AESGCM(sk)
    response = recv_json(conn,aesgcm)
    if not(response):
        return False

    username = response["username"]
    password = response["password"]
    nonceC = bytes.fromhex(response["nonceC"])
    #Verifica la nonce
    if not is_nonce_valid(nonceC):
        print("Handshake error: nonceC is invalid!")
        return False
    
    print("Login try from " + username)

    # A questo punto verifico le credenziali per autenticare il client e manda la risposta
    (auth_success, is_new_user) = check_credentials(username, password)
    if auth_success == None:
        return False

    nonceS = os.urandom(16)
    #Mando il json
    data = {
                "login_result": auth_success,
                "change_pwd": is_new_user,
                "nonceS": nonceS.hex()
            }

    if not(send_json(conn, data, aesgcm)):
        return False


    if not(auth_success): #se le credenziali sono invalide o utente non trovato
        return False
    
    else:#se le credenziali sono ok
        print("Login success")
        if is_new_user:#se l'utente deve cambiare la password, ricevo la nuova_pwd dal client
            
            response = recv_json(conn,aesgcm)
            if not(response):
                return False
            
            new_pwd = response["new_pwd"]
            nonceC = bytes.fromhex(response["nonceC"])
            #Verifica la nonce
            if not is_nonce_valid(nonceC):
                print("Handshake error: nonceC is invalid!")
                return False
            
            #Aggiorno la password dell'utente
            change_pwd = update_user_password(username, new_pwd)
            nonceS = os.urandom(16)
            data = {
                "change_pwd": change_pwd,
                "nonceS": nonceS.hex()
                }
            #invio la risposta
            if not(send_json(conn, data, aesgcm)):
                return False
            
            if not(change_pwd):#Se la pwd non è stata aggiornata correttamente
                print("Error during password update")
                return False
            
            else:#l'utente ha cambiato password correttamente, deve rieffettuare il login per utilizzare il servizio
                print("Password update successfully")
                return False
        else:#Login effettuato da utente che ha già aggiornato la pwd è può utilizzare il servizio, server in attesa.
            return True

def Create_Keys(username: str):
    
    db_conn = open_db_connection()
    if db_conn is None:
        print("Error connecting db")
        return False, 0

    try:
        cursor = db_conn.cursor()

        # Controlla se le chiavi esistono già
        cursor.execute("SELECT private_key, public_key, key_del FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        if not result:
            print("User not found.")
            return False, 0

        private_key_pem, public_key_pem, key_del = result
        
        if private_key_pem is not None and public_key_pem is not None:
            print("Key pair already exists.")
            return True, 0  # Nessuna azione necessaria
        if key_del == 1:#se l'utente ha già eliminato la sua coppia di chiavi non può generarne altre
            print(f"User {username} is not allowed to generate another keypair")
            return True, 1


        # Genera nuova coppia ECC
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Serializza chiave privata cifrata con passphrase
        private_pem_encrypted = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        ).decode()
        #!!!Conservo la private key nella sua encrypted form, con la passhphrase,best aviable encryption usa AES-256!!!

        # Serializza chiave pubblica in chiaro
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Salva nel DB
        cursor.execute(
            "UPDATE users SET private_key = %s, public_key = %s WHERE username = %s",
            (private_pem_encrypted, public_pem, username)
        )
        db_conn.commit()
        print("Key pair generated and stored.")
        return True, 2

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return False, 0

    finally:
        cursor.close()
        db_conn.close()

def Sign_Doc(username: str, doc: bytes):

    db_conn = open_db_connection()
    if db_conn is None:
        print("Error connecting db")
        return "", False

    try:
        #recupero la chiave privata dal db
        cursor = db_conn.cursor()
        cursor.execute("SELECT private_key FROM users WHERE username = %s", (username,))
        row = cursor.fetchone()
        private_key_pem = row[0]
        if private_key_pem is None:
            print("Private key not found for user " + username)
            return "Nokey", False

        encrypted_private_key_pem = row[0].encode()

        # Leggi la passphrase da env
        passphrase = os.getenv("PRIVATE_KEY_PASSPHRASE")
        if passphrase is None:
            print("Error passphrase not set")
            return "", False
        passphrase_bytes = passphrase.encode()

        # Carica la chiave privata decifrata
        private_key = serialization.load_pem_private_key(
            encrypted_private_key_pem,
            password=passphrase_bytes,
        )
    
        # Firma il documento
        signature = private_key.sign(
            doc,
            ec.ECDSA(hashes.SHA256())
        )

        return signature, True

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return "", False

    finally:
        cursor.close()
        db_conn.close()

def Get_Public_Key(username: str):

    db_conn = open_db_connection()
    if db_conn is None:
        print("Error connecting db")
        return False, 0

    try:
        cursor = db_conn.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username = %s", (username,))
        row = cursor.fetchone()

        if row is None:
            print("User not found")
            return False, 0

        public_key_pem = row[0]
        if public_key_pem is None:
            print("Public key not founded for user " + username)
            return False , 1

        return True, public_key_pem

    except mysql.connector.Error as err:
        print(f"Query error: {err}")
        return False, 0

    finally:
        cursor.close()
        db_conn.close()

def Delete_Keys(username: str):

    db_conn = open_db_connection()
    
    if db_conn is None:
        print("Error connecting db.")
        return False , 0

    try:
        cursor = db_conn.cursor()

        # Controlla se l'utente esiste
        cursor.execute("SELECT private_key, public_key, key_del FROM users WHERE username = %s", (username,))
        row = cursor.fetchone()

        if row is None:
            print("User not found.")
            return False, 0

        private_key, public_key, key_del = row

        if key_del == 1:
            print("Keys already deleted for the user " + username)
            return False, 1

        if private_key is None and public_key is None:
            print("No keys to delete for user " + username)
            return False, 2

        # Procedi all'eliminazione logica
        cursor.execute("""
            UPDATE users 
            SET private_key = NULL, public_key = NULL, key_del = 1 
            WHERE username = %s
        """, (username,))
        db_conn.commit()
        print("Keys deleted successfully for user " + username)
        return True, 0

    except mysql.connector.Error as err:
        print(f"Error during db operations: {err}")
        return False, 0

    finally:
        cursor.close()
        db_conn.close()

def handle_services(conn, sk, sk_ct):

    aesgcm = AESGCM(sk)

    #Aspetto che il client scelga un servizio da utilizzare
    while True:

        #Verifico la validità della session key
        if not(session_key_validity(sk_ct)):
            return False
        
        print("\nServer waiting for actions...")
        response = recv_json(conn,aesgcm)
        if not(response):
            continue

        service = int(response["service"])
        username = response["username"]
        nonceC = bytes.fromhex(response["nonceC"])
        #Verifica la nonce
        if not is_nonce_valid(nonceC):
            print("Handshake error: nonceC is invalid!")
            continue
        
        if service == 0: #Log out from user
            print("Logging out: " + username)
            #Mando il json
            nonceS = os.urandom(16)
            data = {
                "status": True,
                "nonceS": nonceS.hex()
                }
            if not(send_json(conn, data, aesgcm)):
                return False
            return False
        
        elif service == 1: #CreateKeys:
            result, flag = Create_Keys(username)
            #se result è true e flag=0, user not allowed, result True e flag=1 le chiavi già esistono no effect, flag=2 op ok
            nonceS = os.urandom(16)
            data = {
                "status": result,
                "flag": flag,
                "nonceS": nonceS.hex()
                }
            if not(send_json(conn, data, aesgcm)):
                return False
            continue

        elif service == 2: #SignDoc:
            document = base64.b64decode(response["document"])
            signature, result = Sign_Doc(username, document)
            nonceS = os.urandom(16)
            if result:
                data = {
                    "status": result,
                    "signature": base64.b64encode(signature).decode(),#codifico in b64 per mandarla in json
                    "nonceS": nonceS.hex()
                    }
            else:
                    data = {
                    "status": result,
                    "signature": signature,
                    "nonceS": nonceS.hex()
                    }
            if not(send_json(conn, data, aesgcm)):
                return False
            continue

        elif service == 3: #GetPublicKey:
            result, pkey = Get_Public_Key(username)
            nonceS = os.urandom(16)
            data = {
                    "status": result,
                    "pkey": pkey,
                    "nonceS": nonceS.hex()
                    }
            if not(send_json(conn, data, aesgcm)):
                return False
            continue
        elif service == 4: #DeleteKeys:
            result, flag = Delete_Keys(username)
            nonceS = os.urandom(16)
            data = {
                    "status": result,
                    "flag": flag,
                    "nonceS": nonceS.hex()
                    }
            if not(send_json(conn, data, aesgcm)):
                return False
            continue

def main():


    while True:
        global nonce_cache
        nonce_cache = {}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(SERVER_ADDR)
        sock.listen(1)
        print("\nServer listening...")
        connection, addr = sock.accept()
        print(f"Connection from {addr}")
        sk, sk_ct = handle_handshake(connection)
        if not(sk):
            connection.close()
            continue
        if not(handle_login(connection, sk, sk_ct)):
            connection.close()
            continue
        #devo mettermi in attesa per far utilizzare i servizi all'utente
        if not(handle_services(connection, sk, sk_ct)):
            connection.close()
            continue

if __name__ == "__main__":
    main()