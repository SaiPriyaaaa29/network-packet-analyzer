from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Ether
import sys
import csv
from datetime import datetime


# ==================================================
# PROJECT TITLE
# ==================================================

print("Network Packet Analyzer")
print("-----------------------")


# ==================================================
# GET FILTER FROM COMMAND LINE
# ==================================================

if len(sys.argv) > 1:
    filter_type = sys.argv[1].lower()
else:
    filter_type = "all"


# ==================================================
# GET PACKET COUNT
# ==================================================

if len(sys.argv) > 2:

    try:
        packet_count = int(sys.argv[2])

        if packet_count <= 0:
            print("\nPacket count must be greater than 0.")
            sys.exit()

    except ValueError:

        print("\nInvalid packet count!")
        print("Example:")
        print("  python analyzer.py dns 20")
        sys.exit()

else:

    packet_count = 10


# ==================================================
# AVAILABLE FILTERS
# ==================================================

filters = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "dns": "udp port 53",
    "https": "tcp port 443"
}


# ==================================================
# CHECK FILTER
# ==================================================

if filter_type == "all":

    bpf_filter = None

elif filter_type in filters:

    bpf_filter = filters[filter_type]

else:

    print("\nInvalid filter!")
    print("Available filters:")
    print("  tcp")
    print("  udp")
    print("  icmp")
    print("  dns")
    print("  https")
    print("  all")

    sys.exit()


print(f"Filter          : {filter_type.upper()}")
print(f"Packet Count    : {packet_count}")
print("Starting packet capture...\n")


# ==================================================
# CSV FILE
# ==================================================

csv_file = "packet_capture.csv"


csv_columns = [
    "Timestamp",
    "Source MAC",
    "Destination MAC",
    "Source IP",
    "Destination IP",
    "TTL",
    "Packet Size",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Application",
    "DNS Query",
    "Resolved IP"
]


# ==================================================
# CREATE CSV FILE
# ==================================================

csv_output = open(
    csv_file,
    "w",
    newline="",
    encoding="utf-8"
)

csv_writer = csv.DictWriter(
    csv_output,
    fieldnames=csv_columns
)

csv_writer.writeheader()


# ==================================================
# PACKET COUNTERS
# ==================================================

total_packets = 0

tcp_packets = 0
udp_packets = 0
icmp_packets = 0
dns_packets = 0
https_packets = 0
other_packets = 0


# ==================================================
# BYTE COUNTERS
# ==================================================

total_bytes = 0
tcp_bytes = 0
udp_bytes = 0
icmp_bytes = 0


# ==================================================
# PACKET ANALYZER
# ==================================================

def analyze_packet(packet):

    global total_packets
    global tcp_packets
    global udp_packets
    global icmp_packets
    global dns_packets
    global https_packets
    global other_packets

    global total_bytes
    global tcp_bytes
    global udp_bytes
    global icmp_bytes

    total_packets += 1

    packet_size = len(packet)

    total_bytes += packet_size

    print("=" * 60)


    # ==================================================
    # TIMESTAMP
    # ==================================================

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    print(f"Timestamp       : {timestamp}")


    # ==================================================
    # DEFAULT CSV VALUES
    # ==================================================

    source_mac = ""
    destination_mac = ""
    source_ip = ""
    destination_ip = ""
    ttl = ""
    protocol_name = ""
    source_port = ""
    destination_port = ""
    application = ""
    dns_query = ""
    resolved_ips = []


    # ==================================================
    # ETHERNET INFORMATION
    # ==================================================

    if Ether in packet:

        source_mac = packet[Ether].src
        destination_mac = packet[Ether].dst

        print(f"Source MAC      : {source_mac}")
        print(f"Destination MAC : {destination_mac}")


    # ==================================================
    # CHECK FOR IP
    # ==================================================

    if IP not in packet:

        other_packets += 1

        protocol_name = "Non-IP"

        print("Non-IP packet")


    else:

        # ==================================================
        # IP INFORMATION
        # ==================================================

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        ttl = packet[IP].ttl

        print(f"Source IP       : {source_ip}")
        print(f"Destination IP  : {destination_ip}")
        print(f"TTL             : {ttl}")
        print(f"Packet Size     : {packet_size} bytes")


        # ==================================================
        # READ IP PROTOCOL
        # ==================================================

        protocol = packet[IP].proto


        # ==================================================
        # TCP
        # ==================================================

        if protocol == 6:

            tcp_packets += 1
            tcp_bytes += packet_size

            protocol_name = "TCP"

            print("Protocol        : TCP")

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            print(f"Source Port     : {source_port}")
            print(f"Destination Port: {destination_port}")
            print(f"TCP Flags       : {packet[TCP].flags}")


            # HTTPS
            if source_port == 443 or destination_port == 443:

                https_packets += 1

                application = "HTTPS"

                print("Application     : HTTPS")


        # ==================================================
        # UDP
        # ==================================================

        elif protocol == 17:

            udp_packets += 1
            udp_bytes += packet_size

            protocol_name = "UDP"

            print("Protocol        : UDP")

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            print(f"Source Port     : {source_port}")
            print(f"Destination Port: {destination_port}")


            # ==================================================
            # DNS
            # ==================================================

            if DNS in packet:

                dns_packets += 1

                application = "DNS"

                print("Application     : DNS")


                # DNS QUERY
                if packet[DNS].qr == 0:

                    if packet[DNS].qd is not None:

                        dns_query = packet[DNS].qd.qname.decode()

                        print(f"DNS Query       : {dns_query}")


                # DNS RESPONSE
                else:

                    print("DNS Response    : Received")


                    if packet[DNS].ancount > 0:

                        for i in range(packet[DNS].ancount):

                            answer = packet[DNS].an[i]

                            # Type 1 = IPv4 A record
                            if answer.type == 1:

                                resolved_ip = str(answer.rdata)

                                resolved_ips.append(resolved_ip)

                                print(
                                    f"Resolved IP     : {resolved_ip}"
                                )


        # ==================================================
        # ICMP
        # ==================================================

        elif protocol == 1:

            icmp_packets += 1
            icmp_bytes += packet_size

            protocol_name = "ICMP"

            print("Protocol        : ICMP")


        # ==================================================
        # OTHER
        # ==================================================

        else:

            other_packets += 1

            protocol_name = "Other"

            print("Protocol        : Other")


    # ==================================================
    # SAVE PACKET TO CSV
    # ==================================================

    csv_writer.writerow({
        "Timestamp": timestamp,
        "Source MAC": source_mac,
        "Destination MAC": destination_mac,
        "Source IP": source_ip,
        "Destination IP": destination_ip,
        "TTL": ttl,
        "Packet Size": packet_size,
        "Protocol": protocol_name,
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Application": application,
        "DNS Query": dns_query,
        "Resolved IP": ", ".join(resolved_ips)
    })

    csv_output.flush()


# ==================================================
# START PACKET CAPTURE
# ==================================================

sniff(
    count=packet_count,
    prn=analyze_packet,
    filter=bpf_filter
)


# ==================================================
# CLOSE CSV
# ==================================================

csv_output.close()


# ==================================================
# CALCULATE PERCENTAGES
# ==================================================

if total_packets > 0:

    tcp_percentage = (tcp_packets / total_packets) * 100
    udp_percentage = (udp_packets / total_packets) * 100
    icmp_percentage = (icmp_packets / total_packets) * 100
    other_percentage = (other_packets / total_packets) * 100

else:

    tcp_percentage = 0
    udp_percentage = 0
    icmp_percentage = 0
    other_percentage = 0


# ==================================================
# FINAL SUMMARY
# ==================================================

print("\n")

print("=" * 60)
print("                 CAPTURE SUMMARY")
print("=" * 60)

print(f"Total Packets : {total_packets}")
print(f"TCP Packets   : {tcp_packets}")
print(f"UDP Packets   : {udp_packets}")
print(f"ICMP Packets  : {icmp_packets}")
print(f"DNS Packets   : {dns_packets}")
print(f"HTTPS Packets : {https_packets}")
print(f"Other Packets : {other_packets}")

print("=" * 60)


# ==================================================
# TRAFFIC STATISTICS
# ==================================================

print("\n")
print("=" * 60)
print("                 TRAFFIC STATISTICS")
print("=" * 60)

print(f"TCP Traffic   : {tcp_percentage:.1f}%")
print(f"UDP Traffic   : {udp_percentage:.1f}%")
print(f"ICMP Traffic  : {icmp_percentage:.1f}%")
print(f"Other Traffic : {other_percentage:.1f}%")

print("=" * 60)


# ==================================================
# BYTE STATISTICS
# ==================================================

print("\n")
print("=" * 60)
print("                  BYTE STATISTICS")
print("=" * 60)

print(f"Total Data    : {total_bytes} bytes")
print(f"TCP Data      : {tcp_bytes} bytes")
print(f"UDP Data      : {udp_bytes} bytes")
print(f"ICMP Data     : {icmp_bytes} bytes")

print("=" * 60)

print("Packet capture completed.")
print(f"Results saved to: {csv_file}")