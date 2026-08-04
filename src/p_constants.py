HEADER_SIZE=24

PCAP_MAGIC = {
    bytes.fromhex("d4c3b2a1"): "little",
    bytes.fromhex("a1b2c3d4"): "big",
}