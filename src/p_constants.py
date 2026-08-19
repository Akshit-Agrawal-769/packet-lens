DEBUG = False
HEADER_SIZE=24
PACKET_RECORD_HEADER_SIZE = 16

def print_banner():
    print("=" * 40)
    print("PacketLens")
    print("=" * 40)

PCAP_MAGIC = {
    bytes.fromhex("d4c3b2a1"): "little",
    bytes.fromhex("a1b2c3d4"): "big",
}

LINK_TYPES = {
    1: "Ethernet",
    105: "IEEE 802.11",
}