import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode() if packet[http.HTTPRequest].Host else ''
        path = packet[http.HTTPRequest].Path.decode() if packet[http.HTTPRequest].Path else ''
        return host + path
    return None

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load.decode(errors='ignore')
        keywords = ["username", "user", "login", "password", "pass", "uname"]
        for keyword in keywords:
            if keyword in payload.lower():
                return payload
    return None

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"[+] IP Packet: {source_ip} -> {destination_ip} | Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            source_port = packet[scapy.TCP].sport
            dest_port = packet[scapy.TCP].dport
            print(f"    [.] TCP Packet: Port {source_port} -> {dest_port}")

        elif packet.haslayer(scapy.UDP):
            source_port = packet[scapy.UDP].sport
            dest_port = packet[scapy.UDP].dport
            print(f"    [.] UDP Packet: Port {source_port} -> {dest_port}")
        
        url = get_url(packet)
        if url:
            print(f"\n[+] HTTP Request >> {url}\n")
            
        login_info = get_login_info(packet)
        if login_info:
            print(f"\n[+] Possible username/password > {login_info}\n")

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"    [.] Payload: {payload[:100]}...") # Print first 100 bytes

if __name__ == "__main__":
    print("Starting network sniffer...")
    
    try:
        sniff("Wi-Fi")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Please ensure you are running the script with root/administrator privileges.")
        print("Also, make sure the interface name is correct.")

