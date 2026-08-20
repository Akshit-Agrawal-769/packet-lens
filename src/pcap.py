from models import (
    GlobalHeader, 
    PacketRecord, 
    EthernetFrame, 
    IPv4Packet, 
    UDPSegment, 
    TCPSegment,
    DNSMessage
    )
import p_constants


def parse_global_header(header: bytes):
    
    magic = header[:4]
    endianness = p_constants.PCAP_MAGIC.get(magic)
    if endianness is None:
        raise ValueError("Invalid PCAP file.")

    major = int.from_bytes(header[4:6],byteorder=endianness)
    minor = int.from_bytes(header[6:8],byteorder=endianness)

    reserved1 = int.from_bytes(header[8:12],byteorder=endianness)
    reserved2 = int.from_bytes(header[12:16],byteorder=endianness)

    snaplen = int.from_bytes(header[16:20],byteorder=endianness)
    linktype = int.from_bytes(header[20:24],byteorder=endianness)

    return GlobalHeader(endianness,major,minor,reserved1,reserved2,snaplen,linktype)


def format_global_header(header: bytes):
    fields = [
        ("Endianness", header.endianness),
        ("Version", f"{header.major_version}.{header.minor_version}"),
        ("Snap Length", f"{header.snaplen} bytes"),
        ("Link Layer", p_constants.LINK_TYPES[header.linktype])]
    return fields


def parse_packet_record(header: bytes, endianness: str):

    seconds = int.from_bytes(header[:4],byteorder=endianness)
    microseconds = int.from_bytes(header[4:8],byteorder=endianness)
    
    length = int.from_bytes(header[8:12],byteorder=endianness)
    length_O = int.from_bytes(header[12:16],byteorder=endianness)

    return PacketRecord(seconds,microseconds,length,length_O)


def format_packet_record(header):
    fields = [
        ("timestamp_seconds", header.timestamp_seconds),
        ("timestamp_microseconds", header.timestamp_microseconds),
        ("captured_length", header.captured_length),
        ("original_length", header.original_length)]
    return fields

def parse_ethernet(data):
    destination = data[:6]
    source = data[6:12]
    ethertype = int.from_bytes(data[12:14], byteorder='big')

    destination_mac = ":".join(f"{byte:02x}" for byte in destination)
    source_mac = ":".join(f"{byte:02x}" for byte in source)

    return EthernetFrame(destination_mac,source_mac,ethertype)

def format_ethernet(data):
    fields = [
        ("destination", data.destination_mac),
        ("source", data.source_mac),
        ("etherType", f"0x{data.ethertype:04x}")]
    return fields

def parse_ipv4(data):
    version = data[0] >> 4
    ihl = data[0] & 0x0F

    dscp_ecn = data[1]

    total_length = int.from_bytes(data[2:4], byteorder="big")
    identification = int.from_bytes(data[4:6], byteorder="big")
    flags_fragment_offset = int.from_bytes(data[6:8], byteorder="big")

    ttl = data[8]
    protocol = data[9]

    checksum = int.from_bytes(data[10:12], byteorder="big")

    source_ip = ".".join(str(byte) for byte in data[12:16])
    destination_ip = ".".join(str(byte) for byte in data[16:20])

    return IPv4Packet(
        version,
        ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        checksum,
        source_ip,
        destination_ip
    )

def format_ipv4(data):
    fields = [
        ("version", data.version),
        ("IHL", data.ihl),
        ("DSCP/ECN", data.dscp_ecn),
        ("total length", data.total_length),
        ("identification", data.identification),
        ("flags/offset", f"0x{data.flags_fragment_offset:04x}"),
        ("TTL", data.ttl),
        ("protocol", data.protocol),
        ("checksum", f"0x{data.checksum:04x}"),
        ("source", data.source_ip),
        ("destination", data.destination_ip)
    ]
    return fields

def parse_udp(data):
    source_port = int.from_bytes(data[:2], byteorder='big')
    destination_port = int.from_bytes(data[2:4], byteorder='big')
    length = int.from_bytes(data[4:6], byteorder='big')
    checksum = int.from_bytes(data[6:8], byteorder='big')

    return UDPSegment(
        source_port,
        destination_port,
        length,
        checksum
    )

def format_udp(data):
    fields = [
        ("source port", data.source_port),
        ("destination port", data.destination_port),
        ("length", data.length),
        ("checksum", f"0x{data.checksum:04x}")
    ]
    return fields

def parse_tcp(data):
    source_port = int.from_bytes(data[0:2], byteorder="big")
    destination_port = int.from_bytes(data[2:4], byteorder="big")

    sequence_number = int.from_bytes(data[4:8], byteorder="big")
    acknowledgement_number = int.from_bytes(data[8:12], byteorder="big")

    data_offset = data[12] >> 4
    flags = data[13]

    window_size = int.from_bytes(data[14:16], byteorder="big")
    checksum = int.from_bytes(data[16:18], byteorder="big")
    urgent_pointer = int.from_bytes(data[18:20], byteorder="big")

    return TCPSegment(
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer
    )

def format_tcp(data):
    fields = [
        ("source port", data.source_port),
        ("destination port", data.destination_port),
        ("sequence number", data.sequence_number),
        ("acknowledgement", data.acknowledgement_number),
        ("data offset", data.data_offset),
        ("flags", f"0x{data.flags:02x}"),
        ("window size", data.window_size),
        ("checksum", f"0x{data.checksum:04x}"),
        ("urgent pointer", data.urgent_pointer)
    ]

    return fields

def parse_dns(data):

    if len(data) < 12:
        raise ValueError('Incomplete DNS header')
    transaction_id = int.from_bytes(data[:2], byteorder='big')
    flags = int.from_bytes(data[2:4], byteorder='big')
    questions = int.from_bytes(data[4:6], byteorder='big')
    answers = int.from_bytes(data[6:8], byteorder='big')
    authority_records = int.from_bytes(data[8:10], byteorder='big')
    additional_records = int.from_bytes(data[10:12], byteorder='big')

    if questions > 0:
        qname = ''
        qtype = 0
        qclass = 0
        i=0
        while data[12+i]!=0:
            j=0
            if i!=0:
                qname+='.'
            l = data[12+i]
            for j in range(l):
                qname+=chr(data[13+i+j])
            i+=l+1
            
        qtype=int.from_bytes(data[13+i:15+i], byteorder='big')
        qclass=int.from_bytes(data[15+i:17+i], byteorder='big')


    return DNSMessage(
        transaction_id,
        flags,
        questions,
        answers,
        authority_records,
        additional_records,
        qname,
        qtype,
        qclass
    )
dns_data = bytes.fromhex(
    "12340100000100000000000006676f6f676c6503636f6d0000010001"
)

dns = parse_dns(dns_data)

print(dns)