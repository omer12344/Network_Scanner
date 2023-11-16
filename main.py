import socket
from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP, Ether
from scapy.layers.l2 import ARP
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from Classes import Ip

# Global variables
LIST_OPEN_IP = []
DICT_PROTOCOLS = {
    "Application": {"DNS": 0, "HTTP": 0},
    "Transport": {"TCP": 0, "UDP": 0},
    "Network": {"DHCP": 0, "ICMP": 0},
    "Link layer": {"ARP": 0, "Ethernet": 0}
}


def ping(host):
    """Ping the specified host to check if it is reachable."""
    ping_packet = IP(dst=str(host)) / ICMP()
    response = sr1(ping_packet, timeout=1, verbose=0)

    if response is None:
        print(f"IP {host} is not open.\n")
    elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
        print(f"IP {host} is open. \n")
        return True
    return False


def put_in_list(ip_address, flag):
    """Create a new Ip object with the given IP address and add it to the list if the flag is True."""
    if flag:
        print(f"Creating object with IP {ip_address} and adding it to the list.\n")
        ip_obj = Ip(ip_address, [], [])
        LIST_OPEN_IP.append(ip_obj)


def create_list_for_ips(ips):
    """Iterate through the list of Ip objects and add all open ports for each IP address to the list."""
    for ip in ips:
        for i in range(20, 1025):
            syn_segment = TCP(dport=i, seq=123, flags="S")
            syn_packet = IP(dst=ip.get_ip()) / syn_segment
            response = sr1(syn_packet, timeout=2, verbose=0)

            if response is None or i == 23:
                print(f"No response from port {i}\n")
            elif "SA" in str(response[TCP].flags):
                print(f"This port is open: {i}")
                ip.set_next_port(str(i))
                print("Creating a client-server communication")
                create_client(str(ip.get_ip()), i)


def create_client(server_ip, server_port):
    """Create a client socket and attempt to establish a normal connection with the server IP and port."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, server_port))
        print(f"Normal connection established successfully between IP {server_ip} and port {server_port}\n")
    except Exception as e:
        print(f"Normal connection failed. {str(e)}")
    finally:
        client_socket.close()


def inspect_packets_local_net(local_net_packets):
    """
    Inspect the packets sent and received on the local network and count the number of packets for each IP address.
    """
    for ip in LIST_OPEN_IP:
        ports_for_sending = {str(port): 0 for port in range(20, 1024)}
        ports_for_receiving = {str(port): 0 for port in ip.get_port_list()}

        packet_stats = {
            'from_src': 0,
            'to_src': 0,
            'dhcp_sent': 0,
            'trs_sent': 0,
            'dhcp_received': 0,
            'trs_received': 0,
        }

        for packet in local_net_packets:
            if str(packet[IP].src) == str(ip.get_ip()):
                packet_stats['from_src'] += 1
                try:
                    protocol = TCP if TCP in packet else UDP
                    ports_for_sending[packet[protocol].sport] += 1
                    packet_stats['trs_sent'] += 1
                except KeyError:
                    packet_stats['dhcp_sent'] += 1
            elif str(packet[IP].dst) == str(ip.get_ip()):
                packet_stats['to_src'] += 1
                try:
                    protocol = TCP if TCP in packet else UDP
                    ports_for_receiving[packet[protocol].dport] += 1
                    packet_stats['trs_received'] += 1
                except KeyError:
                    packet_stats['dhcp_received'] += 1

        ip_report(ip, ports_for_sending, ports_for_receiving, packet_stats)


def ip_report(ip, ports_for_sending, ports_for_receiving, packet_stats):
    print(f"On the local network, IP {ip.get_ip()} sent: {packet_stats['from_src']} packets")
    print(f"The local IP {ip.get_ip()} sent this many DHCP packets: {packet_stats['dhcp_sent']}")
    print(f"The local IP {ip.get_ip()} sent this many transport layer packets: {packet_stats['trs_sent']}")
    print(f"This local IP {ip.get_ip()} sent transport layer packets using these ports:\n")

    for key, value in ports_for_sending.items():
        if value != 0:
            print(f"This port {key} sent this many packets: {value}")

    print(f"On the local network, IP {ip.get_ip()} received: {packet_stats['to_src']} packets")
    print(f"The local IP {ip.get_ip()} received this many DHCP packets: {packet_stats['dhcp_received']}")
    print(f"The local IP {ip.get_ip()} received this many transport layer packets: {packet_stats['trs_received']}")
    print(f"This local IP {ip.get_ip()} received transport layer packets using these ports:\n")

    for key, value in ports_for_receiving.items():
        if value != 0:
            print(f"This port {key} received this many packets: {value}")


def inspect_packets_global_net(list_of_outer_packets):
    """
    Inspect the packets sent from or received by global IPs and count the number of packets for each IP address.
    """
    outer_ips = []
    for p in list_of_outer_packets:
        if str(p[IP].src) not in outer_ips and '192.168.1' not in str(p[IP].src):
            outer_ips.append(str(p[IP].src))
        elif str(p[IP].dst) not in outer_ips and '192.168.1' not in str(p[IP].dst):
            outer_ips.append(str(p[IP].dst))
    packets_sent_from_outer_ips = []
    for i in range(len(outer_ips)):
        packets_sent_from_outer_ips.append(0)
    for i in range(len(outer_ips)):
        for p in list_of_outer_packets:
            if str(p[IP].src) == outer_ips[i]:
                packets_sent_from_outer_ips[i] += 1
    print("These are the global IPs that communicated with our local network:")
    print(outer_ips)
    for i in range(len(outer_ips)):
        print("----------------------------------------------------------------------")
        print("From global IP address: " + str(
            outer_ips[i]) + ", the number of packets sent to our local network were: " + str(
            packets_sent_from_outer_ips[i]))
        create_global_local_dictionary(outer_ips[i], list_of_outer_packets)


def create_global_local_dictionary(outer_ip, list_of_outer_packets):
    """
    Create a dictionary with local IPs as keys and the number of packets sent from
    the outer IP to each local IP as values.
    """
    final_dict = {}
    for ip in open_ips:
        final_dict[str(ip)] = 0
    for packet in list_of_outer_packets:
        if packet[IP].src == outer_ip:
            final_dict[str(packet[IP].dst)] += 1
    print("Detailed explanation about the exchanged packets from " + outer_ip + ":\n")
    for key in final_dict:
        print(str(final_dict[key]) + " packets were sent to this local IP address: " + key + "\n")
        create_port_dictionary(list_of_outer_packets, key, outer_ip)


def create_port_dictionary(list_of_outer_packets, local_ip, outer_ip):
    """
    Create dictionaries with ports as keys and the number of packets sent/received through each port as values.
    """
    global_port = {}
    local_port = {}
    for port in range(20, 65600):
        global_port[str(port)] = 0
        if port > 1024:
            local_port[str(port)] = 0
    for Ip in LIST_OPEN_IP:
        if Ip.get_ip() == local_ip:
            for port in Ip.get_port_list():
                local_port[port] = 0
    count_bad_packets = 0
    for packet in list_of_outer_packets:
        if packet[IP].src == str(outer_ip) and packet[IP].dst == str(local_ip):
            try:
                try:
                    global_port[str(packet[TCP].sport)] += 1
                    local_port[str(packet[TCP].dport)] += 1
                except:
                    global_port[str(packet[UDP].sport)] += 1
                    local_port[str(packet[UDP].dport)] += 1
            except Exception as e1:
                print(str(e1))
                count_bad_packets += 1
    print("From this global IP " + str(outer_ip) + " to this local IP " + local_ip + ":\n")
    if count_bad_packets != 0:
        print(str(count_bad_packets) + " packets were below the transport layer")
    count = 0
    for key in global_port:
        if global_port[key] != 0:
            print("Global IP " + str(outer_ip) + " used this port " + str(key) +
                  " for sending this many packets: " + str(global_port[key]))
            count += 1
    for key in local_port:
        if local_port[key] != 0:
            print("Local IP " + str(local_ip) + " used this port " + str(key) +
                  " for receiving this many packets: " + str(local_port[key]))
            count += 1
    if count == 0:
        print("0 ports were in use because all packets exchanged were below the transport layer,"
              " or 0 packets were exchanged between them.")
    print("----------------------------------------------------------------------")


def filter_tcp_udp(packet):
    """
    Filter TCP and UDP packets.
    """
    return IP and (TCP in packet or UDP in packet)


def sniff_packets(open_ips):
    """
    Sniff packets on the network, separate them into local and global packets, and inspect their protocols.
    """
    print("sniffing...")
    packets = sniff(filter="ip", count=1000, lfilter=filter_tcp_udp, timeout=10)
    print("sniffed all packets")
    local_net_packets = []
    global_net_packets = []
    broadcast_flag = False
    for packet in packets:
        if packet[IP].dst == '255.255.255.255' or packet[IP].src == '255.255.255.255':
            broadcast_flag = True
            local_net_packets.append(packet)
        if packet[IP].dst == '0.0.0.0' or packet[IP].src == '0.0.0.0':
            broadcast_flag = True
            local_net_packets.append(packet)
        if broadcast_flag is False:
            flag = False
            for ip in LIST_OPEN_IP:
                if "192.168.1" in packet[IP].src and "192.168.1" in packet[IP].dst:
                    flag = True
                    break
            if flag:
                local_net_packets.append(packet)
            else:
                global_net_packets.append(packet)
    for packet in packets:
        if HTTP in packet:
            DICT_PROTOCOLS["Application"]["HTTP"] += 1
        if DNS in packet:
            DICT_PROTOCOLS["Application"]["DNS"] += 1
        if TCP in packet:
            DICT_PROTOCOLS["Transport"]["TCP"] += 1
        elif UDP in packet:
            DICT_PROTOCOLS["Transport"]["UDP"] += 1
        if DHCP in packet:
            DICT_PROTOCOLS["Network"]["DHCP"] += 1
        if ICMP in packet:
            DICT_PROTOCOLS["Network"]["ICMP"] += 1
        if ARP in packet:
            DICT_PROTOCOLS["Link layer"]["ARP"] += 1
        if Ether in packet:
            DICT_PROTOCOLS["Link layer"]["Ethernet"] += 1
    for key in DICT_PROTOCOLS:
        print("From layer: " + str(key))
        for key2 in DICT_PROTOCOLS[key]:
            print("From protocol " + str(key2) + ", the number of packets: " + str(DICT_PROTOCOLS[key][key2]))
    print()
    inspect_packets_local_net(local_net_packets)
    inspect_packets_global_net(global_net_packets)


def get_local_ip():
    """
    Get the local IP address of the machine.
    """
    try:
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))
        local_ip = temp_socket.getsockname()[0]
        temp_socket.close()
        return local_ip
    except socket.error:
        return "Unable to determine IP address"


# MAIN:
LIST_OPEN_IP = []
for i in range(1, 255):
    host = f'192.168.1.{i}'
    put_in_list(host, ping(host))

DICT_PROTOCOLS = {
    "Application": {
        "DNS": 0,
        "HTTP": 0
    },
    "Transport": {
        "TCP": 0,
        "UDP": 0
    },
    "Network": {
        "DHCP": 0,
        "ICMP": 0
    },
    "Link layer": {
        "ARP": 0,
        "Ethernet": 0
    }
}

open_ips = [get_local_ip()]
create_list_for_ips(LIST_OPEN_IP)
if LIST_OPEN_IP is not None:
    for ip in LIST_OPEN_IP:
        if ip is not None:
            ip.print_ip()
            open_ips.append(str(ip.get_ip()))

sniff_packets(open_ips)
