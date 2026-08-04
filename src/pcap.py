from models import GlobalHeader
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