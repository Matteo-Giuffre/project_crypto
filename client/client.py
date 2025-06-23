import mysql.connector
import bcrypt
import os
import sys
import random
import time
import getpass
import json
import base64

from tkinter import Tk
from tkinter.filedialog import askopenfilename

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socket

SERVER_ADDR = ('localhost', 12345)

DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': 'crypto',
    'database': 'crypto_project',
    'port': 3306,
    'ssl_disabled': False 
}

nonce_cache = {}

def open_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"Connection error: {err}")
        return None

def send_json(sock, data_dict, aesgcm):

    plaintext = json.dumps(data_dict).encode()
    nonce_aes = os.urandom(12)  # AES-GCM nonce
    ciphertext = aesgcm.encrypt(nonce_aes, plaintext, None)
    try:
        # Invia nonce_AES + ciphertext con lunghezze
        sock.sendall(len(nonce_aes).to_bytes(2, 'big') + nonce_aes)
        sock.sendall(len(ciphertext).to_bytes(4, 'big') + ciphertext)
        return True
    except Exception as e:
        print(f"Error in send_json: {e}")
        return False

def recv_json(sock, aesgcm):
    try:
        len_nonce = int.from_bytes(sock.recv(2), 'big')
        nonce = sock.recv(len_nonce)

        len_cipher = int.from_bytes(sock.recv(4), 'big')
        ciphertext = sock.recv(len_cipher)

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
    expiration = 60 * 30  # 30 minuti, tempo di validità della sessione
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

def register_user(username: str):

    conn = open_db_connection()
    if conn is None:
        print("Error connecting db")
        return True

    cursor = conn.cursor()

    # Genera password temporanea: username + "temp" + 4 cifre random
    random.seed(time.time())
    rand_num = random.randint(0, 9999)
    temp_password = f"{username}temp{rand_num:04d}"

    # bcrypt lavora con bytes, quindi converto la password in bytes
    password_bytes = temp_password.encode()
    # genero hash bcrypt con salt automatico (default cost 12)
    hashed_password_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    # decodifico il risultato in stringa per salvarlo sul db
    hashed_password = hashed_password_bytes.decode()

    try:
        # Inserisco nel DB
        sql = "INSERT INTO users (username, password) VALUES (%s, %s)"
        cursor.execute(sql, (username, hashed_password))
        conn.commit()

        print(f"\nRegistration complete for user {username}")
        print(f"This is your temporary password: {temp_password}")

        # Salvo la chiave pubblica in dss_public.pem
        cursor.execute("SELECT key_data FROM dss_public_key WHERE id = 1")
        row = cursor.fetchone()
        if row and row[0]:
            with open("dss_public.pem", "w") as f:
                f.write(row[0])
            print("Publick key saved in dss_public.pem")
        else:
            print("Error: public key not found.")

    except mysql.connector.IntegrityError as e:
        if e.errno == 1062:
            print(f"Error: username '{username}' already used.")
        else:
            print(f"Database error: {e}")
        return False
    finally:
        cursor.close()
        conn.close()
    return True

def perform_handshake(sock):

    # 1.Il client genera ECDHE keypair ephimeral_secret_key_Client e ephimeral_public_key_Client
    eskC = ec.generate_private_key(ec.SECP256R1())
    epkC = eskC.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint) #serialize public key
    #Genero la nonceC
    nonceC = os.urandom(16)

    try:
    # 2. Invio [epkC, nonceC]
        sock.sendall(len(epkC).to_bytes(2,'big') + epkC)
        sock.sendall(len(nonceC).to_bytes(2,'big') + nonceC)
    except Exception as e:
        print("Error in data sending:", e)
        return False, False

    # 3. Ricevo [epkS, nonceS, signature] dal server
    try:
    
        len_epkS = int.from_bytes(sock.recv(2), 'big')
        epkS = sock.recv(len_epkS)
    except Exception as e:
        print("Error in data receiving:", e)
        return False, False

    len_nonceS = int.from_bytes(sock.recv(2), 'big')
    nonceS = sock.recv(len_nonceS)

    #Verifico la nonce
    if not is_nonce_valid(nonceS):
        print("Handshake error: nonceS is invalid!")
        return False, False

    len_sig = int.from_bytes(sock.recv(2), 'big')
    signature = sock.recv(len_sig)

    # Carico la chiave pubblica DSS server per verifica firma
    with open("dss_public.pem", "rb") as f:
        dss_pub = load_pem_public_key(f.read())

    # 4. Verifico firma: Sign(skS, epkS || epkC || nonceC || nonceS)
    signed_data = epkS + epkC + nonceC + nonceS
    try:
        dss_pub.verify(
            signature,
            signed_data,
            ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        print("Hanshake Error: invalid Signature:", e)
        return False, False
    
    # Shared secret con ECDH
    server_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epkS) #deserialize public key
    shared_secret = eskC.exchange(ec.ECDH(), server_pub_key)

    #5. Derivo chiave AES dalla shared secret (HKDF)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonceC + nonceS,
        info=b'handshake data',
    ).derive(shared_secret)
    session_key_creation_time = time.time()

    return session_key, session_key_creation_time

def login_user(username, password, sock, session_key, sk_ct):

    #una volta stabilito il canale di comunicazione sicuro ed autenticato il server gli mando username e password,
    #da questo momento in poi in formato json per autenticare anche il client
    #Invia E(sessionkey, "username || pwd || nonceC") con AES-GCM per farsi autenticare dal server

    #Verifico la validità della session key
    if not(session_key_validity(sk_ct)):
        return None, None
    
    aesgcm = AESGCM(session_key)

    nonceC = os.urandom(16)
    data = {
        "username": username,
        "password": password,
        "nonceC": nonceC.hex()  # JSON non supporta i bytes → uso .hex()
    }

    #Invio il json al server
    if not(send_json(sock, data, aesgcm)):
        return None, None

    #Ricevo il json di risposta del login dal server
    response = recv_json(sock, aesgcm)
    if not(response):
        return None, None
    nonceS = bytes.fromhex(response["nonceS"])
    #Verifica la nonce
    if not is_nonce_valid(nonceS):
        print("Handshake error: nonceC is invalid!")
        return None, None
      
    return response["login_result"], response["change_pwd"]

def change_password(session_key, sk_ct, sock, new_pwd):

    #Verifico la validità della session key
    if not(session_key_validity(sk_ct)):
        return False
    
    aesgcm = AESGCM(session_key)

    #Mando la nuova password al server
    nonceC = os.urandom(16)
    data = {
        "new_pwd": new_pwd,
        "nonceC": nonceC.hex()  # JSON non supporta i bytes → uso .hex()
    }
    if not(send_json(sock, data, aesgcm)):
        return False

    #Ricevo il json di risposta dal server
    response = recv_json(sock, aesgcm)
    if not(response):
        return False
    nonceS = bytes.fromhex(response["nonceS"])
    #Verifica la nonce
    if not is_nonce_valid(nonceS):
        print("Handshake error: nonceC is invalid!")
        return False
    
    return response['change_pwd']

def logout_user(sock, sk, sk_ct, username):

    #Verifico la validità della session key
    if not(session_key_validity(sk_ct)):
        return None
    
    aesgcm = AESGCM(sk)

    nonceC = os.urandom(16)
    data = {
        "service": 0,
        "username": username,
        "nonceC": nonceC.hex()  # JSON non supporta i bytes → uso .hex()
    }

    #Invio il json al server
    if not(send_json(sock, data, aesgcm)):
        return False

    #Ricevo il json di risposta del login dal server
    response = recv_json(sock, aesgcm)
    if not(response):
        return False
    nonceS = bytes.fromhex(response["nonceS"])
    #Verifica la nonce
    if not is_nonce_valid(nonceS):
        print("Handshake error: nonceC is invalid!")
        return False
    
    return response['status']

def CreateKeys(sock, sk, sk_ct, username):

    #Verifico la validità della session key
    if not(session_key_validity(sk_ct)):
        return None
    
    aesgcm = AESGCM(sk)

    nonceC = os.urandom(16)
    data = {
        "service": 1,
        "username": username,
        "nonceC": nonceC.hex()  # JSON non supporta i bytes → uso .hex()
    }

    #Invio il json al server
    if not(send_json(sock, data, aesgcm)):
        return None

    #Ricevo il json di risposta del login dal server
    response = recv_json(sock, aesgcm)
    if not(response):
        return None
    
    if not(response['status']):
        print("Error during operation")
        return False
    nonceS = bytes.fromhex(response["nonceS"])
    #Verifica la nonce
    if not is_nonce_valid(nonceS):
        print("Handshake error: nonceC is invalid!")
        return None

    return True, response["flag"]

def SignDoc(sock, sk, sk_ct, username):

    #Verifico la validità della session key
    if not(session_key_validity(sk_ct)):
        return None

    aesgcm = AESGCM(sk)

    Tk().withdraw()#visualizzazione grafica per scelta docuento
    file_path = askopenfilename(title="Select document to sign")
    if not file_path:
        print("No file selected.")
        return False

    with open(file_path, "rb") as f:
        document = f.read()

    nonceC = os.urandom(16)
    data = {
        "service": 2,
        "username": username,
        "document": base64.b64encode(document).decode(),# file binario codificato base64
        "nonceC": nonceC.hex()  # JSON non supporta i bytes → uso .hex()
    }

    #Invio il json al server
    if not(send_json(sock, data, aesgcm)):
        return None

    #Ricevo il json di risposta dal server con lo status e la signature
    response = recv_json(sock, aesgcm)
    if not(response):
        return None
    
    if not(response['status']):
        if response['signature'] == "Nokey":
          print("No keypair found for user " + username)
        else:
            print("Error during operation")
        return False
    nonceS = bytes.fromhex(response["nonceS"])
    #Verifica la nonce
    if not is_nonce_valid(nonceS):
        print("Handshake error: nonceC is invalid!")
        return None

    # Estraggo la firma
    signature = base64.b64decode(response["signature"])#decodifica da b64 in bytes
    if not signature or signature == None or signature == "":
        print("Error receving signature.")
        return None

    # Salva firma
    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as sig_file:
        sig_file.write(signature)

    print(f"Document successfully signed by {username} and saved in:\n {sig_path}")
    return True

def GetPublicKey(sock, sk, sk_ct, username):

    #Verifico la validità della session key
    if not(session_key_validity(sk_ct)):
        return None, None
    
    aesgcm = AESGCM(sk)

    nonceC = os.urandom(16)
    data = {
        "service": 3,
        "username": username,
        "nonceC": nonceC.hex()  # JSON non supporta i bytes → uso .hex()
    }

    #Invio il json al server
    if not(send_json(sock, data, aesgcm)):
        return None, None

    #Ricevo il json di risposta del login dal server
    response = recv_json(sock, aesgcm)
    if not(response):
        return None, None 
    
    if not(response['status']):
        if response["pkey"] == 1:
            print("Public key not founded for user " + username)
        else:
            print("Error during operation")
        return False, False
    nonceS = bytes.fromhex(response["nonceS"])
    #Verifica la nonce
    if not is_nonce_valid(nonceS):
        print("Handshake error: nonceC is invalid!")
        return None, None

    return True, response["pkey"]

def DeleteKeys(sock, sk, sk_ct, username):

    #Verifico la validità della session key
    if not(session_key_validity(sk_ct)):
        return None
    
    aesgcm = AESGCM(sk)

    nonceC = os.urandom(16)
    data = {
        "service": 4,
        "username": username,
        "nonceC": nonceC.hex()  # JSON non supporta i bytes → uso .hex()
    }

    #Invio il json al server
    if not(send_json(sock, data, aesgcm)):
        return None

    #Ricevo il json di risposta del login dal server
    response = recv_json(sock, aesgcm)
    if not(response):
        return None
    
    if not(response['status']):
        if response["flag"] == 1:
            print("Keys already deleted for the user " + username)
        elif response["flag"] == 2:
            print("No keys to delete for user " + username)
        else:
            print("Error during operation")
        return False
    nonceS = bytes.fromhex(response["nonceS"])
    #Verifica la nonce
    if not is_nonce_valid(nonceS):
        print("Handshake error: nonceC is invalid!")
        return None

    return True

def main():
    global nonce_cache
    #Menù
    while True:
        nonce_cache = {}#svuoto la cache delle nonce ogni volta che avvio una nuova sessione
        print("\n\t\t\t  Employee Client\n")
        print("1) Registration")
        print("2) Login")
        print("0) Exit")

        try:
            scelta = int(input())
        except ValueError:
            print("ERROR, insert a number between 0 and 2!")
            continue

        if scelta == 0:
            print("\nGoodbye!\n")
            break
        elif scelta == 1:
            username = input("Choose a Username: ").strip()
            if username == "":
                print("Username cannot be empty.")
                continue
            register_user(username)
            continue
        elif scelta == 2:
            username = input("Username: ").strip()
            if username == "":
                print("Username cannot be empty.")
                continue
            password = getpass.getpass("Password: ").strip()

            #Creo la connessione col server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(SERVER_ADDR)
            
            # Chiamo la funzione per eseguire l'handshake
            sk, sk_ct = perform_handshake(sock)
            
            #Controllo che non ci siano stati errori di comunicazione
            if not(sk):
                print("Handshake Error.")
                sock.close()
                continue
            
            #Eseguo il login con l'invio delle credenziali sul canale di comunicazione sicuro
            #Prendo in risposta login_response: True le credenziali sono valide
            #change_pwd per capire se l'utente è al primo accesso e deve cambiare la password
            login_response, change_pwd = login_user(username, password,sock, sk, sk_ct)
            
            #Controllo se c'è stato un errore nella comunicazione del login (ex. parsing json error)
            if login_response == None:
                print("Log in error")
                sock.close()
                continue

            #Gestisco i vari casi
            if login_response == False:
                print("Invalid credentials")
                sock.close()
                continue
            #Se il login è ok verifico se l'utente deve impostare la pwd(primo login) oppure no
            else:
                if change_pwd:
                    print("\nHi " + username + ", please choose a new password to use the service.")
                    new_password = getpass.getpass("New Password: ").strip()
                    if not(change_password(sk, sk_ct, sock, new_password)):
                        print("Error during password updating")
                        continue
                    else:
                        print("Password changed successfully, please log in again to use the service")
                        continue
                else:
                #Login effetuato con successo senza bisogna di aggiornare la password,
                # l'utente può quindi utilizzare effettivamente i servizi del dss server
                    while True:
                        print("\n\t\t\t  Digital Signature Service\n")
                        print("1) CreateKeys")
                        print("2) SignDoc")
                        print("3) GetPublicKey")
                        print("4) DeleteKeys")
                        print("0) Logout")

                        try:
                            scelta2 = int(input())
                        except ValueError:
                            print("ERROR, insert a number between 0 and 4!")
                            continue

                        if scelta2 == 0:#Log out

                            if not(logout_user(sock, sk ,sk_ct, username)):
                                print("Error in communication, restart the server!")
                            else:
                                print("\nGoodbye " + username + "!\n")
                            sock.close()
                            break

                        elif scelta2 == 1:#CreateKeys

                            result, flag = CreateKeys(sock, sk, sk_ct, username)
                            if result == None:
                                sock.close()
                                break
                            elif result == True:
                                if flag == 0:
                                    print("\nKey pair already exists for user: " + username)
                                elif flag == 1:
                                    print(f"User {username} is not allowed to generate another keypair")
                                else:
                                    print("\nKey pair generated successfully for user: " + username)
                            else:
                                pass
                            continue

                        elif scelta2 == 2:#SignDoc

                            result = SignDoc(sock, sk, sk_ct, username)
                            if result == None:
                                sock.close()
                                break
                            elif result == True:
                                pass
                            else:
                                pass
                            continue

                        elif scelta2 == 3:#GetPublicKey

                            result, pkey = GetPublicKey(sock, sk, sk_ct, username)
                            if result == None:
                                sock.close()
                                break
                            elif result == True:
                                print(username + ", this is your Public Key:\n\n" + pkey)
                            else:
                                pass
                            continue
                        elif scelta2 == 4:

                            result = DeleteKeys(sock, sk, sk_ct, username)
                            if result == None:
                                sock.close()
                                break
                            elif result == True:
                                print("Keys deleted successfully for user " + username)
                            else:
                                pass
                            continue

                        else:
                            print("\nERROR, insert a number between 0 and 4!")
                            continue

        else:
            print("\nERROR, insert a number between 0 and 2!")
            continue

if __name__ == "__main__":
    main()