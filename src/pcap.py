def parse_magic_number(header: bytes):
    magic = header[:4]

    if magic == bytes.fromhex("d4c3b2a1"):
        return {
            "endianness": "little",
            "valid": True
        }

    elif magic == bytes.fromhex("a1b2c3d4"):
        return {
            "endianness": "big",
            "valid": True
        }

    return {
        "valid": False
    }