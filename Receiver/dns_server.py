import socket
import logging
import struct
import os
from scapy.all import *
from aes_encrypt import encrypt_message
from cloakify import Cloakify
from packetWhisper import TransferCloakedFile
os.environ["SRC_IP"] = "127.0.0.1"
os.environ["EOT"] = "False"
os.environ["EOTUrl"] = "endOfTransmission.google.com"


def request_retransmit(seq_id):
    cipher = "ciphers\\common_fqdn\\topWebsites"
    cloaked_restrasmission = "cloaked_retramission.txt"
    Cloakify('�{seq_id}', cipher, cloaked_restrasmission)
    TransferCloakedFile(cloaked_restrasmission, 0.0, os.environ["SRC_IP"])
    fqdn_array = []
    with open(cloaked_restrasmission, 'r') as file:
        fqdn_array = [line.strip() for line in file]

    with open('cloaked_response.txt', 'r') as file:
        fqdn_array = [line.strip() for line in file]
        for fqdn in fqdn_array:
            if fqdn_array.index(fqdn) >= seq_id:
                id = int(fqdn_array.index(fqdn))
                dns_req = IP(dst=os.environ["SRC_IP"])/UDP(dport=53)/DNS(rd=1, qd=DNSQR(unicastresponse=1, qname=fqdn))
                dns_req[DNS].id = id
                send(dns_req, verbose=0)
                print(f"Requesting retrasmision packet {id}")


def get_dns_request_id(data):
    """
    Extracts the ID value from a DNS request.

    :param data: The raw DNS request data
    :return: The ID value as an integer
    """
    if len(data) < 2:
        raise ValueError("Data is too short to contain a valid DNS request")
    
    # The ID is the first 2 bytes of the DNS request
    dns_id = struct.unpack('!H', data[:2])[0]
    return dns_id


def decode_dns_ptr(data):
    """Decodifica un record DNS PTR da una stringa di byte.

    Args:
        data: Una stringa di byte contenente un record DNS PTR.

    Returns:
        Una stringa contenente il nome di dominio decodificato.
    """

    offset = 12  # Salta i primi 12 byte (header)
    domain_name = ""

    while data[offset] != 0:
        length = data[offset]
        domain_name += data[offset+1:offset+length+1].decode('ascii') + '.'
        offset += length + 1

    # Inverti l'ordine dei label
    domain_name = domain_name[:-1]  # Rimuovi il punto finale
    domain_name = ".".join((domain_name.split(".")))

    return domain_name

def append_domain(line):
    with open('cloaked.payload', 'a') as file:
        with open('ciphers\\common_fqdn\\topWebsites') as f:
            for domain in f:
                if line in domain:
                    file.write(line + '\n')

def is_dns_query_of_type_a(data):
    # DNS query type A is represented by 0x0001 in the query section
    try:
        # Extract the question section
        question_section = data[12:]
        # Skip the query name
        while question_section[0] != 0:
            question_section = question_section[1 + question_section[0]:]
        # Extract the query type and class
        query_type, query_class = struct.unpack('!HH', question_section[1:5])
        return query_type == 1  # Type A
    except Exception as e:
        logging.error(f"Error parsing DNS query: {e}")
    return False

def start_udp_server(start_id=0):
    # Configure logging
    logging.basicConfig(level=logging.INFO)

    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket
        server_address = ('localhost', 53)
        sock.bind(server_address)
        logging.info(f"Server started on {server_address}")

        # Receive data
        seq_id = 0
        received_packets = set()  # Registro per tracciare gli ID dei pacchetti già ricevuti

        while True:
            try:
                data, address = sock.recvfrom(4096)
                os.environ['SRC_IP'] = address[0]
                #logging.info(f"Received {len(data)} bytes from {address}")
                response = data 
                FQDN = decode_dns_ptr(data)
                
                if FQDN == os.environ["EOTUrl"]:
                    os.environ["EOT"] = "True"
                    print("End of transmission received.")
                    return
                
                if is_dns_query_of_type_a(data): 
                    with open('ciphers\\common_fqdn\\topWebsites', 'r') as f:
                        top_websites = [line.strip() for line in f]  # Crea una lista delle righe del file
                        if FQDN.strip() not in top_websites:  # Confronta con le righe lette
                            print(f"Domain {FQDN} is not in the top websites list. Ignoring., seq_id: {get_dns_request_id(data)}")
                            continue

                    packet_id = get_dns_request_id(data)
                    print("Expected seq_id:", seq_id)
                    print("Received packet_id:", packet_id)
                    print("Received FQDN:", FQDN)
                    
                    if packet_id in received_packets:
                        print(f"Duplicate packet detected: {packet_id}. Ignoring.")
                    elif seq_id != packet_id:
                        print(f"Packet mismatch: Expected {seq_id}, but got {packet_id}")
                        print("Requesting re-transmission.")
                        request_retransmit(seq_id)
                        # Non incrementiamo seq_id qui perché il pacchetto non è corretto
                    else:
                        print(f"Packet {seq_id} received correctly")
                        if seq_id >= start_id:
                            append_domain(FQDN)
                        received_packets.add(packet_id)
                        seq_id += 1  # Incrementiamo solo quando riceviamo il pacchetto corretto
                
                # Send the response to the client
                sock.sendto(response, address)
            except Exception as e:
                logging.error(f"Error receiving data: {e}")


    except Exception as e:
        logging.error(f"Error starting server: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    start_udp_server()