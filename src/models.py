from dataclasses import dataclass

@dataclass
class GlobalHeader:
    endianness: str
    major_version: int
    minor_version: int
    reserved1: int
    reserved2: int
    snaplen: int
    linktype: int


@dataclass
class PacketRecord:
    timestamp_seconds: int
    timestamp_microseconds: int
    captured_length: int
    original_length: int

@dataclass
class Packet:
    number: int
    record: PacketRecord
    layers: list

@dataclass
class EthernetFrame:
    destination_mac: str
    source_mac: str
    ethertype: int

@dataclass
class IPv4Packet:
    version: int
    ihl: int
    dscp_ecn: int
    total_length: int
    identification: int
    flags_fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    source_ip: str
    destination_ip: str

@dataclass
class UDPSegment:
    source_port: int
    destination_port: int
    length: int
    checksum: int

@dataclass
class TCPSegment:
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgement_number: int
    data_offset: int
    flags: int
    window_size: int
    checksum: int
    urgent_pointer: int

@dataclass
class DNSMessage:
    transaction_id: int
    flags: int
    questions: int
    answers: int
    authority_records: int
    additional_records: int

    query_name: str
    query_type: int
    query_class: int