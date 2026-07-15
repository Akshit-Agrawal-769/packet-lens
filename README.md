# PacketLens

A network packet analyzer written in Python, built from scratch.

PacketLens reads PCAP files and turns raw packet bytes into something you can actually read and reason about — Ethernet frames, IP packets, TCP/UDP traffic, DNS queries, HTTP requests — all broken down in plain, human-readable output.

## Why I'm building this

Tools like Wireshark are incredible, but they're also black boxes if you've never looked inside one. I wanted to actually understand how a raw stream of bytes off the wire turns into "this is a TCP packet going from port 51000 to port 443." The only way I know how to really learn that is to build it myself: parse the headers by hand, get the byte offsets wrong a bunch of times, and eventually have something that works.

So PacketLens is equal parts tool and learning project. If you're a student, a developer curious about networking, or someone getting into security, I'm hoping it's useful to you the same way it's been useful to me — as a hands-on way to see what's actually happening in network traffic instead of just reading about it.

## Status

🚧 Early days. This is v0.1 and very much a work in progress — expect rough edges, missing features, and APIs that might change as I figure out what actually makes sense.

## Where things stand

- [ ] Read PCAP files
- [ ] Decode Ethernet frames
- [ ] Decode IPv4 packets
- [ ] Decode TCP segments
- [ ] Decode UDP datagrams
- [ ] Decode DNS packets
- [ ] Decode HTTP requests/responses
- [ ] Protocol statistics
- [ ] Packet filtering
- [ ] JSON export
- [ ] Command-line interface

Nothing's checked off yet because nothing's shipped yet. This list will get updated as pieces land.

## Getting started

There's not a lot to run yet, but once there is:

```bash
git clone https://github.com/yourusername/packetlens.git
cd packetlens
pip install -r requirements.txt
```

Usage instructions and examples will show up here as the CLI takes shape.
