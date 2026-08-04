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