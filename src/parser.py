from pcap import (
    parse_ethernet,
    parse_ipv4,
    parse_udp,
    parse_tcp
)

from models import IPv4Packet, UDPSegment, TCPSegment


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

def get_tcp_flags(flags):

    flag_names = []

    if flags & 0x01:
        flag_names.append("FIN")
    if flags & 0x02:
        flag_names.append("SYN")
    if flags & 0x04:
        flag_names.append("RST")
    if flags & 0x08:
        flag_names.append("PSH")
    if flags & 0x10:
        flag_names.append("ACK")
    if flags & 0x20:
        flag_names.append("URG")
    if flags & 0x40:
        flag_names.append("ECE")
    if flags & 0x80:
        flag_names.append("CWR")

    return flag_names


def summarize_packet(layers):

    ip = None
    tcp = None
    udp = None

    for layer in layers:

        if isinstance(layer, IPv4Packet):
            ip = layer
        elif isinstance(layer, TCPSegment):
            tcp = layer
        elif isinstance(layer, UDPSegment):
            udp = layer

    if ip is None:
        return 'Unknown Packet'

    if tcp is not None:
        flag=get_tcp_flags(tcp.flags)
        flag_out=''
        if flag:
            flag_out=f' [{', '.join(flag)}]'
        return (
            f'TCP  '
            f'{ip.source_ip}:{tcp.source_port} -> '
            f'{ip.destination_ip}:{tcp.destination_port}'
            f'{flag_out}'
        )

    if udp is not None:
        return (
            f'UDP  '
            f'{ip.source_ip}:{udp.source_port} -> '
            f'{ip.destination_ip}:{udp.destination_port}'
        )

    return (
        f'IPv4  '
        f'{ip.source_ip} -> {ip.destination_ip}'
    )

def get_protocol(layers):

    for layer in layers:
        if isinstance(layer, TCPSegment):
            return "TCP"
        elif isinstance(layer, UDPSegment):
            return "UDP"

    return "OTHER"

def matches_filter(layers,protocol_filter,port_filter=None):

    protocol=get_protocol(layers)

    if protocol_filter !='all':
        if protocol.lower()!=protocol_filter:
            return False

    if port_filter is not None:
        for layer in layers:
            if isinstance(layer,TCPSegment):
                if(layer.source_port != port_filter
                    and layer.destination_port != port_filter):
                    return False
                return True
            elif isinstance(layer,UDPSegment):
                if(layer.source_port != port_filter
                    and layer.destination_port != port_filter):
                    return False
                return True
        return False
    return True