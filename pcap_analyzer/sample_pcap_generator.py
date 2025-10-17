"""
Sample PCAP File Generator
Creates normal and suspicious PCAP files for testing
"""

from scapy.all import *
import random
import time

def create_normal_pcap():
    """Create a normal network traffic PCAP"""
    print("📁 Creating normal_traffic.pcap...")
    
    packets = []
    timestamp = time.time()
    
    # Normal HTTP traffic to common websites
    websites = ["google.com", "facebook.com", "github.com", "stackoverflow.com"]
    for website in websites:
        # HTTP GET requests (normal pattern)
        pkt = Ether()/IP(dst="8.8.8.8")/TCP(dport=80, sport=random.randint(10000, 60000))/Raw(load=f"GET / HTTP/1.1\r\nHost: {website}\r\n\r\n")
        packets.append(pkt)
        
        # HTTP responses (normal pattern)
        pkt = Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/TCP(sport=80, dport=random.randint(10000, 60000))/Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        packets.append(pkt)
    
    # Normal DNS queries (spread out)
    domains = ["google.com", "yahoo.com", "microsoft.com", "apple.com"]
    for domain in domains:
        pkt = Ether()/IP(dst="8.8.8.8")/UDP(dport=53, sport=random.randint(10000, 60000))/DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(pkt)
    
    # Normal SSH connections
    for i in range(3):
        pkt = Ether()/IP(dst=f"192.168.1.{i+10}")/TCP(dport=22, sport=random.randint(10000, 60000), flags="S")
        packets.append(pkt)
    
    # Normal HTTPS traffic
    for i in range(5):
        pkt = Ether()/IP(dst="8.8.8.8")/TCP(dport=443, sport=random.randint(10000, 60000), flags="A")
        packets.append(pkt)
    
    wrpcap("normal_traffic.pcap", packets)
    print("✅ Created normal_traffic.pcap - Normal browsing patterns")

def create_dos_attack_pcap():
    """Create a PCAP with DoS (Denial of Service) attack patterns"""
    print("📁 Creating dos_attack_traffic.pcap...")
    
    packets = []
    target_ip = "192.168.1.100"
    
    print("   🚨 Adding SYN Flood patterns...")
    # SYN Flood - Rapid connection requests
    for i in range(200):  # High volume of SYN packets
        pkt = Ether()/IP(src=f"10.0.0.{random.randint(1, 254)}", dst=target_ip)/TCP(dport=80, sport=random.randint(1000, 65535), flags="S")
        packets.append(pkt)
    
    print("   🚨 Adding UDP Flood patterns...")
    # UDP Flood - High volume UDP packets
    for i in range(150):
        pkt = Ether()/IP(src=f"172.16.0.{random.randint(1, 254)}", dst=target_ip)/UDP(dport=random.randint(1, 65535), sport=random.randint(1000, 65535))/Raw(load="X"*random.randint(100, 500))
        packets.append(pkt)
    
    print("   🚨 Adding ICMP Flood patterns...")
    # ICMP Flood - Ping of Death style
    for i in range(100):
        pkt = Ether()/IP(src=f"192.168.2.{random.randint(1, 254)}", dst=target_ip)/ICMP()/Raw(load="PING"*50)
        packets.append(pkt)
    
    print("   🚨 Adding HTTP Flood patterns...")
    # HTTP Flood - Many HTTP requests
    for i in range(100):
        pkt = Ether()/IP(src=f"10.1.1.{random.randint(1, 254)}", dst=target_ip)/TCP(dport=80, sport=random.randint(10000, 60000))/Raw(load=f"GET / HTTP/1.1\r\nHost: target.com\r\n\r\n")
        packets.append(pkt)
    
    wrpcap("dos_attack_traffic.pcap", packets)
    print("✅ Created dos_attack_traffic.pcap - Denial of Service patterns")

def create_reconnaissance_pcap():
    """Create a PCAP with Reconnaissance/Scanning attack patterns"""
    print("📁 Creating reconnaissance_traffic.pcap...")
    
    packets = []
    target_network = "192.168.1."
    
    print("   🔍 Adding Port Scanning patterns...")
    # Port Scanning - Sequential port scanning
    scanner_ip = "10.0.0.50"
    for port in range(20, 120):  # Scanning common ports
        pkt = Ether()/IP(src=scanner_ip, dst=f"{target_network}100")/TCP(dport=port, flags="S")
        packets.append(pkt)
    
    print("   🔍 Adding Network Sweeping patterns...")
    # Network Sweeping - Scanning multiple hosts
    for host in range(1, 50):  # Scanning first 50 hosts
        pkt = Ether()/IP(src=scanner_ip, dst=f"{target_network}{host}")/ICMP()
        packets.append(pkt)
    
    print("   🔍 Adding Service Detection patterns...")
    # Service Detection - Checking multiple services
    services = [21, 22, 23, 25, 53, 80, 110, 443, 3389]
    for service in services:
        pkt = Ether()/IP(src=scanner_ip, dst=f"{target_network}100")/TCP(dport=service, flags="S")
        packets.append(pkt)
    
    print("   🔍 Adding OS Fingerprinting patterns...")
    # OS Fingerprinting - Different TCP flag combinations
    flags_combinations = ["S", "SF", "SA", "FA"]
    for flags in flags_combinations:
        pkt = Ether()/IP(src=scanner_ip, dst=f"{target_network}100")/TCP(dport=80, flags=flags)
        packets.append(pkt)
    
    print("   🔍 Adding DNS Zone Transfer attempts...")
    # DNS Reconnaissance
    pkt = Ether()/IP(src=scanner_ip, dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype="AXFR"))
    packets.append(pkt)
    
    wrpcap("reconnaissance_traffic.pcap", packets)
    print("✅ Created reconnaissance_traffic.pcap - Network scanning patterns")

if __name__ == "__main__":
    print("🎯 Generating sample PCAP files for testing...")
    print("=" * 50)
    
    create_normal_pcap()
    print()
    create_dos_attack_pcap() 
    print()
    create_reconnaissance_pcap()
    
    print("\n🎉 All sample PCAP files created successfully!")
    print("\n📊 Files Created:")
    print("   1. normal_traffic.pcap - Regular browsing patterns")
    print("   2. dos_attack_traffic.pcap - Denial of Service attacks") 
    print("   3. reconnaissance_traffic.pcap - Network scanning attacks")
    print("\n🔍 These match the attack types your model was trained to detect!")
