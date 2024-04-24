from scapy.all import sniff, TCP, UDP, DNS, IP


#Scan TCP
def scanTCP(timeout=10):
    tcpList = []
    #Sniff tcp packets, will timeout after 10 seconds
    packets = sniff(filter="tcp", timeout=timeout)

    # Check for TCP packets which are then added into the list
    for packet in packets:
        if TCP in packet:
            tcpinfo={
                "Source IP:": packet[IP].src,
                "Source Port:": packet[TCP].sport,
                "Destination Port:": packet[TCP].dport
            }
            tcpList.append(tcpinfo)

    return tcpList

#Scan UDP
def scanUDP(timeout=10):
    udpList = []
    packets = sniff(filter="udp", timeout=timeout)
    for packet in packets:
        if UDP in packet and IP in packet:
            udpinfo={
                "Source IP:": packet[IP].src,
                "Source Port:": packet[UDP].sport,
                "Destination Port:": packet[UDP].dport
            }
            udpList.append(udpinfo)

    return udpList
#Scan DNS
def scanDNS(timeout=25): #Timeout is higher as it did not scan any on 10 seconds
    dnsList = []
    # Sniff DNS packets over UDP and TCP
    packets = sniff(filter="(udp port 53) or (tcp port 53)", timeout=timeout)
    for packet in packets:
        if DNS in packet:
            if UDP in packet: #depending on whether packets are TCP or UDP it will find the destination and source port respectively.
                sourceport = packet[UDP].sport
                destinationport = packet[UDP].dport
            elif TCP in packet: 
                sourceport = packet[TCP].sport
                destinationport = packet[TCP].dport
            else:
                continue

            dnsinfo={
                "Source IP:": packet[IP].src,
                "Source Port:": sourceport,
                "Destination Port:": destinationport
            }
            dnsList.append(dnsinfo)

    return dnsList

def scanHTTP(timeout=30):
    httpList=[]

    # Sniff HTTP traffic
    packets = sniff(filter="tcp port 80", timeout=timeout)

    # Check for HTTP packets and extract source IP addresses
    for packet in packets:
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80: #Checks destination and source ports for 80/Http traffic
                httpinfo={
                "Source IP:": packet[IP].src,
                "Source Port:": packet[TCP].sport,
                "Destination Port:": packet[TCP].dport
            }
                httpList.append(httpinfo)

    return httpList

def scanLDAP(timeout=35):
    ldapList=[]

    packets = sniff(filter="tcp and port 389", timeout=timeout) #Will sniff for TCP on port 389 which is the default for LDAP 
    for packet in packets:
        if packet.haslayer(TCP):
            ldapinfo={
                "Source IP:": packet[IP].src,
                "Source Port:": packet[TCP].sport,
                "Destination Port:": packet[TCP].dport
            }
            ldapList.append(ldapinfo)


def main():
    #Scan and Print TCP traffic
    print("TCP Servers:")
    print(scanTCP())

    #Scan and Print UDP traffic
    print("\nUDP Servers:")
    print(scanUDP())

    #Scan and Print DNS traffic
    print("\nDNS Servers:")
    print(scanDNS())

    #Scan and Print HTTP traffic
    print("\nHTTP Servers:")
    print(scanHTTP())

    print("\nLDAP Servers:")
    print(scanLDAP())

if __name__ == "__main__":
    main()