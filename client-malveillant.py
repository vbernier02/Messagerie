#client
from tkinter import *
from tkinter import messagebox
import socket
import threading
import hashlib
import random
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
HOST = 'localhost'
PORT = 5000

client_socket.connect((HOST, PORT))

pseudo = None

#p du client de base
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74F379E9D6D56A60E9E66F4F51567069B517E515B503E47C2F8AB205B9D4602A7F56C1B46E392C8D8B61766F153AB0CFAAF9EBC25D6F60AC7D38B9FF1B3D36B1DB399DA6F1F9538EC1E8F885B168F43BE212C7CE61C4B31A5BB9E55DBF1C8B7E1E222BB2598C9AEE4D35455754B3D9784E13A35C237D35ADCA95C343D8E0E8D820A2F46771F8B163F1E15555D92F53846999E6FBAB340F4F6F1EC3494B47CE6B1CFCDA8BD29CC981F83B0B015D3F9AEFC95D5F2E1F71F3AA8A8E0B54218B8A48C3F68F8D6431F46295B94DAAF7D5A0632F4747D8C3425A8EF563EED48B6D1255A38F2E00675A01ABF6E1A9EF532A
#p modifié
#p = 99999999999999

#g du client de base
g = 2
#g modifié
#g = 8

private_key = None
public_key = None
commun_key = None
rsa_public_key = None
rsa_private_key = None
rsa_public_keys_others = {}
stop_event = threading.Event()

def initialiser_interface_pseudo():
    def valider_pseudo():
        global pseudo, rsa_public_key, rsa_private_key
        pseudo = zone_pseudo.get()
        groupe = zone_groupe.get()
        
        if pseudo.strip() and groupe.strip():
            info = json.dumps({"pseudo": pseudo, "groupe": groupe})
            client_socket.sendall(info.encode())  
            confirmation = client_socket.recv(1024).decode()
            if confirmation == "GROUPE_PLEIN":
                messagebox.showerror("Erreur", "Le groupe plein.")
                client_socket.close()
                return
            elif confirmation == "GROUPE_OK":
                print(f"{pseudo} a rejoint le groupe : {groupe}")
                
                interface_pseudo.destroy()
                generate_keys()
                
                if commun_key:
                    initialiser_interface()
                else:
                    client_socket.close()
        else:
            messagebox.showerror("Erreur", "Veuillez entrer un pseudo et un groupe valide.")

    interface_pseudo = Tk()
    interface_pseudo.title("Connexion")
    interface_pseudo.geometry("300x200")
    Label(interface_pseudo, text="Entrez votre pseudo :").pack(pady=5)
    zone_pseudo = Entry(interface_pseudo)
    zone_pseudo.pack(pady=5)
    Label(interface_pseudo, text="Entrez le groupe :").pack(pady=5)
    zone_groupe = Entry(interface_pseudo)
    zone_groupe.pack(pady=5)
    Button(interface_pseudo, text="Valider", command=valider_pseudo).pack(pady=5)
    interface_pseudo.protocol("WM_DELETE_WINDOW", lambda: client_socket.close() or interface_pseudo.destroy())
    interface_pseudo.mainloop()


def generate_keys():

    global private_key, public_key, commun_key, rsa_public_key, rsa_private_key
    #clé dh aléatoire de base
    private_key = random.randint(2, p - 2)
    #clé anormale
    #private_key = 999999
    public_key = pow(g, private_key, p)
    client_socket.sendall(str(public_key).encode())
    other_public_keys1 = int(client_socket.recv(4096).decode())
    shared_key = pow(other_public_keys1, private_key, p)
    client_socket.sendall(str(shared_key).encode())
    other_public_keys2 = int(client_socket.recv(4096).decode())
    commun_key = pow(other_public_keys2, private_key, p)

    commun_key = hashlib.sha256(str(commun_key).encode()).digest()
    print("Échange Diffie-Hellman terminé.")

    rsa_public_key, rsa_private_key = gen_rsa_keypair(2048)
    if rsa_public_key is None or rsa_private_key is None:
        print("Erreur : Génération de clef RSA")
        client_socket.close()
        return
    print("Génération de clé RSA terminée.")

    if rsa_public_key is None:
        print("Erreur : rsa_public_key")
        return

    envoye_rsa()
    reception_clés()

def envoye_rsa():
    global rsa_public_key
    n, e = rsa_public_key
    clef_rsa = f"{n},{e}"
    client_socket.sendall(clef_rsa.encode())

def reception_clés(): 
    for _ in range(2):
        rsa_keys = client_socket.recv(4096).decode()
        try:
            data = json.loads(rsa_keys)
            sender = data["pseudo"]
            rsa_key = data["rsa_key"]
            rsa_public_keys_others[sender] = rsa_key
        except json.JSONDecodeError:
            print(f"Erreur : message JSON")

def gen_rsa_keypair(bits):
    size = bits // 2
    p = getPrime(size)
    q = getPrime(size)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    assert (((p - 1) % e != 0) and ((q - 1) % e != 0))
    d = inverse(e, phi_n)
    publique = (n, e)
    privée = (n, d)
    return publique, privée    

def encrypt_message(symmetric_key, message):
    cipher = AES.new(symmetric_key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

    return iv + ciphertext

def decrypt_message(symmetric_key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext.decode()

def hacher_message(message):
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)

def signer_message(private_key, message):
    n, d = private_key
    message_hash = hacher_message(message)
    signature = pow(message_hash, d, n)
    return signature

def verifier_signature(public_key, message, signature):
    n, e = public_key
    message_hash = hacher_message(message)
    decrypted_hash = pow(signature, e, n)
    return decrypted_hash == message_hash

def envoi_messages():
    global rsa_private_key
    message = zone_texte.get()
    if message.strip():
        full_message = f"{pseudo}:{message}"
        signature = signer_message(rsa_private_key, full_message)
        
        message_data = json.dumps({
            "message": full_message,
            "signature": signature
        })
        encrypted_data = encrypt_message(commun_key, message_data)

        while True:
            client_socket.sendall(encrypted_data)

        zone_affichage.config(state=NORMAL)
        zone_affichage.insert(END, f"{pseudo} : {message}\n")
        zone_affichage.config(state=DISABLED)
    zone_texte.delete(0, END)

def réception_messages():
    while True:
        try:
            message_encrypt = client_socket.recv(1024)
            if message_encrypt == "Connexion fermé par un utilisateur":
                client_socket.close()
                break
            if not message_encrypt:
                break

            message_data = decrypt_message(commun_key, message_encrypt)
            data = json.loads(message_data)
            full_message = data["message"]
            signature = int(data["signature"])
            sender, message = full_message.split(":", 1)
            
            if sender in rsa_public_keys_others:
                sender_public_key = rsa_public_keys_others[sender]
                sender_public_key = tuple(map(int, sender_public_key.split(",")))
                
                if verifier_signature(sender_public_key, full_message, signature):
                    zone_affichage.config(state=NORMAL)
                    zone_affichage.insert(END, f"{sender} : {message}\n")
                    zone_affichage.config(state=DISABLED)
                else:
                    print(f"Signature invalide de {sender}")
            else:
                print(f"Clef de {sender} absente")
        except Exception as e:
            print(f"Erreur lors de la réception des messages : {e}")
            break
    client_socket.close()


def fermeture():
    if messagebox.askokcancel("Quitter", "Fermer la connection ?"):
        stop_event.set()  
        client_socket.close()
        root.destroy() 

def initialiser_interface():
    global root, zone_affichage, zone_texte, réception_thread
    
    root = Tk()
    root.title("Utilisateur : " + pseudo)
    zone_affichage = Text(root, state=DISABLED)
    zone_affichage.pack()
    zone_texte = Entry(root)
    zone_texte.pack()
    envoyer = Button(root, text="Envoyer", command=envoi_messages)
    envoyer.pack()
    quitter = Button(root, text="Quitter", command=fermeture)
    quitter.pack()
    root.bind('<Return>', lambda event : envoi_messages()) #envoyer des messages avec la touche entrée
    réception_thread = threading.Thread(target=réception_messages, daemon=True)
    réception_thread.start()
    root.protocol("WM_DELETE_WINDOW", fermeture)
    root.mainloop()


if __name__ == "__main__":
    initialiser_interface_pseudo()
