from models import GlobalHeader, PacketRecord, EthernetFrame
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


def format_packet_record(header: bytes):
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