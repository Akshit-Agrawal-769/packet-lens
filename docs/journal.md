Current questions:

- How does the receiver know a packet is missing?
- How long should it wait before assuming the packet is lost?
- How are packets put back in order?
- How do two computers agree on the format of a packet?
- How can corrupted packets be detected?

These notes are to document my understanding while building PacketLens.
The goal is not to summarize networking textbooks but to record the reasoning behind the design of modern computer networks.

# Packets

Networks send packets instead of large messages
- small units make communication more reliable and efficient

## Engineering Tradeoffs

### Benefits

- Efficient bandwidth usage
- Fair sharing among multiple users
- data corruption localised and easy retransmission
- Better scalability

### Costs

- Large data chunks are more predictable
- no problem statement for reordering and arranging packets in the correct order
- less complexity and channels for data loss
- data might be smaller than packet size leading to inefficiency
  
> Achieving the correct packet size.

> Smaller packets improve reliability but increase protocol overhead.
Larger packets reduce overhead but make retransmissions more expensive.

## Additional Thoughts
- difference between differentiable and non-diefferentiable graphs when thinking in terms of channel.
<br><br>
# Routing

Packets contain only their **final destination**.
Graph thinking and BFS implementation becomes terrific due to scalibility.
Each router makes only the next forwarding decision based on its own knowledge.
This greatly reduces complexity because routers do not need to map the its vasteness,the Internet.

**next-hop routing** is what this evolved to become

## Engineering Principle:
> Large global systems are often built from many small local decisions.
Examples include GPS navigation, distributed systems, and Internet routing.


# Binary Files

Reading a file does not meant "reading packets."
The operating system simply returns raw bytes.
Packets only exist after the parser assigns structure to those bytes.
Bytes have no inherent meaning.
The same sequence of bytes could represent

- text
- an integer
- an image
- executable instructions
- a packet header

Meaning comes from an agreed interpretation.

## Engineering Principle
>Data and meaning are separate concepts.
>A parser's job is not to create information.
>Its job is to correctly interpret existing bytes according to an agreed specification.

## Questions answered
- Why don't routers store the entire Internet?
- Why don't packets carry their complete route?
- Why do computers have multiple identities (IP, MAC, hostname)?
- Why is a binary file just bytes until interpreted?
- Why isn't a filename enough to identify a file?
