import socket

def start_udp_server():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Set the SO_REUSEADDR option
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to the address and port
    server_address = ('', 53)  # Listen on all interfaces on port 53
    sock.bind(server_address)

    #print("Listening on UDP port 53...")
    
    while True:
        # Wait for incoming data
        data, address = sock.recvfrom(4096)  # Buffer size is 4096 bytes
        print(f"Received {len(data)} bytes from {address}: {data}")

if __name__ == "__main__":
    start_udp_server()