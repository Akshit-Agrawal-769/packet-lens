from pcap import (
    parse_ethernet,
    parse_ipv4,
    parse_udp,
    parse_tcp
)


def parse_packet(data):
    layers = []

    # Ethernet
    ethernet = parse_ethernet(data)
    layers.append(ethernet)

    if ethernet.ethertype != 0x0800:
        return layers

    # IPv4
    ip_data = data[14:]
    ipv4 = parse_ipv4(ip_data)
    layers.append(ipv4)

    # Finding where IPv4 metadata begins
    ip_header_length = ipv4.ihl * 4
    transport_data = ip_data[ip_header_length:]

    # TCP
    if ipv4.protocol == 6:
        tcp = parse_tcp(transport_data)
        layers.append(tcp)

    # UDP
    elif ipv4.protocol == 17:
        udp = parse_udp(transport_data)
        layers.append(udp)

    return layers