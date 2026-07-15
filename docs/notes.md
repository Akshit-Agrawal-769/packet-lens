Current questions:

- How does the receiver know a packet is missing?
- How long should it wait before assuming the packet is lost?
- How are packets put back in order?
- How do two computers agree on the format of a packet?
- How can corrupted packets be detected?

These notes are to document my understanding while building PacketLens.
The goal is not to summarize networking textbooks but to record the reasoning behind the design of modern computer networks.

# Packets

Networks send packets instead of large messages because-
- small units make communication more reliable and efficient
- efficient bandwidth usage
- allow many users to share the same network(avoiding big roadblocks)
- data corruption can be localised
- scalable
### Tradeoff
- Large data chunks are more predictable
- no problem statement for reordering and arranging packets in the correct order
- less complexity and channels for data loss
- data might be smaller than packet size leading to inefficiency
  
 > Achieving the correct packet size. balancing complexity and reliability

# Routing

Packets contain only their **final destination**.
Each router makes only the next forwarding decision based on its own knowledge.
This greatly reduces complexity because routers do not need a complete map of the Internet.


**next-hop routing** is the technical term

Engineering Principle:
> Large global systems are often built from many small local decisions.
Examples include GPS navigation, distributed systems, and Internet routing.
