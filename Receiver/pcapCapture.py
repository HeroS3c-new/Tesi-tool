import sys
from scapy.all import sniff, wrpcap
from scapy.layers.dns import DNS

def capture_pcap(filename='cloaked_command.pcap'):
    target_domain = 'endOfTransmission.google.com.'
    def packet_callback(packet):
        nonlocal found
        if DNS in packet and packet[DNS].qr == 0:
            #print(f"Richiesta DNS: {packet[DNS].qd.qname.decode()}")
            if packet[DNS].qd.qname.decode() == target_domain:
                print(f"Intercettata richiesta per {target_domain}. Salvo il pcap e termino.")
                found = True
                wrpcap(filename, packets)
                sys.exit(0)
        packets.append(packet)

    packets = []
    found = False
    sniff(prn=packet_callback, store=0)
    
    
if __name__ == "__main__":
    capture_pcap()