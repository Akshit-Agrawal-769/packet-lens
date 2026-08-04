from models import GlobalHeader, PacketRecord
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