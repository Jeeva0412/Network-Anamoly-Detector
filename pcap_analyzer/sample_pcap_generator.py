
"""
Sample PCAP File Generator
Creates normal and suspicious PCAP files for testing
"""

from scapy.all import *
import random

def create_normal_pcap():
    """Create a normal network traffic PCAP"""
    print("📁 Creating normal_traffic.pcap...")
    
    packets = []
    
    # Normal HTTP traffic to common websites
    websites = ["google.com", "facebook.com", "github.com", "stackoverflow.com"]
    for website in websites:
        # HTTP GET requests
        pkt = Ether()/IP(dst="8.8.8.8")/TCP(dport=80)/Raw(load=f"GET / HTTP/1.1\r\nHost: {website}\r\n\r\n")
        packets.append(pkt)
        
        # HTTP responses (simplified)
        pkt = Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/TCP(sport=80)/Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        packets.append(pkt)
    
    # Normal DNS queries
    domains = ["google.com", "yahoo.com", "microsoft.com", "apple.com"]
    for domain in domains:
        pkt = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(pkt)
    
    # Some normal TCP connections
    for i in range(5):
        pkt = Ether()/IP(dst=f"192.168.1.{i+10}")/TCP(dport=443, flags="S")
        packets.append(pkt)
    
    wrpcap("normal_traffic.pcap", packets)
    print("✅ Created normal_traffic.pcap")

def create_suspicious_pcap():
    """Create a suspicious network traffic PCAP"""
    print("📁 Creating suspicious_traffic.pcap...")
    
    packets = []
    
    # Port scanning behavior (highly suspicious)
    print("   Adding port scanning patterns...")
    target_ip = "192.168.1.1"
    for port in range(80, 100):  # Scanning multiple ports
        pkt = Ether()/IP(src="10.0.0.100", dst=target_ip)/TCP(dport=port, flags="S")
        packets.append(pkt)
    
    # UDP flood pattern
    print("   Adding UDP flood patterns...")
    for i in range(100):
        pkt = Ether()/IP(src=f"10.0.0.{random.randint(1, 50)}", dst="192.168.1.50")/UDP(dport=random.randint(1000, 9999))/Raw(load="X"*random.randint(50, 200))
        packets.append(pkt)
    
    # Suspicious protocol patterns
    print("   Adding suspicious protocol traffic...")
    suspicious_protocols = [7, 19, 123, 161, 162]  # Echo, chargen, NTP, SNMP
    for protocol in suspicious_protocols:
        pkt = Ether()/IP(src="10.0.0.100", dst="192.168.1.1")/IP(proto=protocol)/Raw(load="SUSPICIOUS")
        packets.append(pkt)
    
    # Rapid fire connections (potential DoS)
    print("   Adding rapid connection patterns...")
    for i in range(50):
        pkt = Ether()/IP(src=f"10.0.0.{random.randint(100, 200)}", dst="192.168.1.80")/TCP(dport=80, flags="S")
        packets.append(pkt)
    
    wrpcap("suspicious_traffic.pcap", packets)
    print("✅ Created suspicious_traffic.pcap")

def create_malware_pcap():
    """Create a PCAP with malware-like patterns"""
    print("📁 Creating malware_traffic.pcap...")
    
    packets = []
    
    # Beaconing behavior (malware calling home)
    for i in range(20):
        pkt = Ether()/IP(src="192.168.1.50", dst="45.33.32.156")/TCP(dport=4444)/Raw(load=f"BEACON_{i}")
        packets.append(pkt)
    
    # Data exfiltration pattern
    pkt = Ether()/IP(src="192.168.1.50", dst="185.199.108.153")/TCP(dport=8080)/Raw(load="EXFILTRATED_DATA"*10)
    packets.append(pkt)
    
    # DNS tunneling attempt
    pkt = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="zgz9e8j3d2k1m4p7.example.com"))
    packets.append(pkt)
    
    wrpcap("malware_traffic.pcap", packets)
    print("✅ Created malware_traffic.pcap")

if __name__ == "__main__":
    print("🎯 Generating sample PCAP files for testing...")
    print("=" * 50)
    
    create_normal_pcap()
    print()
    create_suspicious_pcap() 
    print()
    create_malware_pcap()
    
    print("\n🎉 All sample PCAP files created successfully!")
    print("   You can now test the analyzer with these files.")