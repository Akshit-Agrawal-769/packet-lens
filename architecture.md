# Architecture

PacketLens follows a modular architecture.

High-level pipeline

PCAP File
      │
      ▼
 Packet Reader
      │
      ▼
 Protocol Parsers
      │
      ▼
 Statistics Engine
      │
      ▼
 Output Layer
