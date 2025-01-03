import socket
import logging
import struct
import os
os.environ["SRC_IP"] = "127.0.0.1"
os.environ["EOT"] = "False"
os.environ["EOTUrl"] = "endOfTransmission.google.com"


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

def start_udp_server():
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
        while True:
            try:
                data, address = sock.recvfrom(4096)
                os.environ['SRC_IP'] =  address[0]
                logging.info(f"Received {len(data)} bytes from {address}")

                # Process the data (example: echo the received data)
                response = data 
                FQDN = decode_dns_ptr(data)
                print(get_dns_request_id(data)) # Seq id of the packet (to check if any packets are missing)
                if FQDN == os.environ["EOTUrl"]:
                    os.environ["EOT"] = "True"
                    print("End of transmission received.")
                    return
                if is_dns_query_of_type_a(data):
                    if seq_id != get_dns_request_id(data):
                        print(f"Packet missing: {seq_id}")
                        print("requesting re-transmission")
                        # Aggiungere chiamata alla funzione di retrasmissione
                    else:
                        seq_id += 1
                        append_domain(FQDN)

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