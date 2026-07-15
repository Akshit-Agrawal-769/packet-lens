# Design Decisions

## Decision 1

Project Name

PacketLens

Reason

The project aims to inspect and understand network traffic rather than simply dump packet contents.

The name reflects exploration instead of low-level parsing.


## Decision 2

PacketLens will initially parse the PCAP file format manually.

Reason

The goal is to understand how packet captures are stored before using higher-level networking libraries.
the implementation would rely only on Python's standard library.
