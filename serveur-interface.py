import socket
import threading
import json

SERVEUR_HOST = 'localhost'
SERVEUR_PORT = 5000
groupes = {}
rsa_public_keys = {}
public_keys = {}
public_keys2 = {}

def gestion_client(conn, adresse):
    nb_clients=3

    try:
        data = conn.recv(1024).decode()
        info = json.loads(data)
        pseudo = info.get("pseudo")
        groupe = info.get("groupe")
        print(f"{pseudo} souhaite rejoindre le groupe : {groupe}")

        if groupe not in groupes:
            groupes[groupe] = []
            public_keys[groupe] = []
            public_keys2[groupe] = [None] * nb_clients
        if len(groupes[groupe]) < nb_clients:
            groupes[groupe].append((conn, pseudo))
        else:
            conn.sendall("GROUPE_PLEIN".encode())
            conn.close()
            return

        conn.sendall("GROUPE_OK".encode())       
        print(f"{pseudo} rejoint le groupe : {groupe}")
        
        client_public_key = int(conn.recv(1024).decode())
        size_dh_key = len(str(client_public_key)) 
        if (size_dh_key < 650 or size_dh_key >660) :
            print("Mauvaise taille de clé dh.")
            return
        public_keys[groupe].append((conn, client_public_key))
        
        
        while len(public_keys[groupe]) < nb_clients:
            pass

        client_index = next(i for i, (c, _) in enumerate(public_keys[groupe]) if c == conn)
        previous_index = (client_index - 1) % len(public_keys[groupe])
        previous_public_key = public_keys[groupe][previous_index][1]

        conn.sendall(str(previous_public_key).encode())
        client_public_key2 = int(conn.recv(1024).decode())

        public_keys2[groupe][client_index] = (conn, client_public_key2)

        while None in public_keys2[groupe]:
            pass

        next_index = (client_index - 1) % len(public_keys2[groupe])
        next_public_key = public_keys2[groupe][next_index][1]       
        conn.sendall(str(next_public_key).encode())

        clef_rsa = conn.recv(1024).decode()
        size_rsa_key = len(str(clef_rsa))
        if (size_rsa_key != 623):
            print("Mauvaise taille de clé rsa.")
            return
        
        rsa_public_keys[conn] = clef_rsa
        while len(rsa_public_keys) < nb_clients:
            pass

        for client, _ in groupes[groupe]:
            if client != conn:
                data = json.dumps({"pseudo": pseudo, "rsa_key": clef_rsa})
                client.sendall(data.encode())
                
        while True:
            data = conn.recv(4096)
            if not data:
                break
            for client, _ in groupes[groupe]:
                if client != conn:
                    client.sendall(data)
                    
    except Exception as e:
        print(f"Erreur avec {pseudo} : {e}")
    finally:
        if groupe in groupes and conn in [c for c, _ in groupes[groupe]]:
            groupes[groupe] = [(c, p) for c, p in groupes[groupe] if c != conn]
            if not groupes[groupe]:
                del groupes[groupe]
                del public_keys[groupe]
                del public_keys2[groupe]
            if conn in rsa_public_keys:
                del rsa_public_keys[conn]
            conn.close()
            print(f"{pseudo} s'est déconnecté.")

def start_serveur():
    serveur_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serveur_socket.bind((SERVEUR_HOST, SERVEUR_PORT))
    serveur_socket.listen()
    print(f"Serveur en attente de connexions sur {SERVEUR_HOST}:{SERVEUR_PORT}...")

    while True:
        conn, adresse = serveur_socket.accept()
        threading.Thread(target=gestion_client, args=(conn, adresse)).start()

start_serveur()
