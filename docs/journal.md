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
> Packetization separates the unit of application data from the unit of network transmission.
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

<br>
Current questions:

- Why does TCP need a handshake but UDP doesn't?
- What is a "connection" if there's no dedicated wire?
- Why do checksums exist if IP already exists?
- Why does DNS use compression pointers instead of just repeating names?
- Is HTTP really "just text," or is that a simplification that breaks somewhere?

# TCP

TCP has to simulate something that doesn't actually exist at the packet level: an ordered, reliable stream. Packets arrive independently, out of order, sometimes twice, sometimes not at all. 
>The network itself delivers independent packets. TCP makes those packets appear to the application as one continuous byte stream.
## Engineering Tradeoffs

### Benefits
- Reliable delivery, the sender knows what arrived
- In-order delivery, the application never sees the reordering
- Flow control, a slow receiver can signal "send less"

### Costs
- Handshake overhead before any data moves
- State has to be tracked on both ends (sequence numbers, windows, retransmit timers)
- A lost segment can prevent later-arriving bytes from being delivered to the application until the missing sequence range is recovered.

> Reliability isn't a property of the network. It's a property TCP fakes on top of a network that has none.

## Additional thoughts
The three-way handshake stopped feeling arbitrary once I framed it as: both sides need to agree on a *starting number*, not just agree to talk. SYN isn't "hello," it's "here's where my counting begins." That's the whole reason sequence numbers exist — without an agreed starting point, "in order" is meaningless.

Flags (SYN, ACK, FIN, RST) aren't really "packet types" the way I first assumed — they're closer to a state machine's transition signals riding inside an otherwise ordinary packet.

<br><br>

# UDP

UDP is like "TCP but worse". UDP isn't TCP without features, it's the solution to a different PS:<br>  *what if reliability costs more than the data is worth?*

## Engineering Tradeoffs

### Benefits
- No handshake, data goes out immediately
- No head of line blocking, one lost packet doesn't stall the rest
- Lower overhead per packet, no connection state to track

### Costs
- No delivery guarantee at all
- No ordering guarantee
- The application has to build any reliability it needs, from scratch, itself

> UDP doesn't remove reliability. It moves the decision of whether reliability is worth the cost from the protocol to the application.

## Questions answered
- Why does TCP need a handshake but UDP doesn't?<br> because TCP promises an ordered stream and needs agreed starting sequence numbers to keep that promise; UDP promises nothing, so there's nothing to agree on first.
- What is a "connection" if there's no dedicated wire?<br> it's just shared state (sequence numbers, windows) that both ends independently track and keep in sync. There's no wire, just synchronized bookkeeping.
<br>

# TCP vs UDP
reliable v/s unreliable would be wrong framing
>TCP = stateful transport with reliability,
      ordering, flow control, congestion control, etc.

>UDP = minimal datagram transport;
      applications decide what additional semantics they need.

<br><br>

# DNS

Parsing DNS is like parsing a structure that isn't flat. Ethernet, IP, TCP, UDP headers are all "linear in a way"  fixed offsets. DNS names are variable-length and can *point backward into the same packet* instead of repeating themselves.
>Compression introduces a second dimension into the parser.

## Why compression exists
A name like `s-ring.msedge.net` might appear in the question section and then again in an answer record. Repeating it in full every time wastes bytes in a protocol that's supposed to be small and cheap. So instead of repeating the name, DNS lets a record say "same name as the one at byte offset N," using the top two bits of a length byte (`0xC0`) as a signal that what follows is a pointer.

## Engineering Tradeoffs

### Benefits
- Smaller packets when the same name repeats (a query and its answer usually share a name)
- No real limit on how much repetition can be compressed away.

### Costs
- The parser can no longer assume "linear parsing". It has to be able to jump backward into bytes it already consumed
- A malicious or corrupted packet can construct a pointer that jumps to itself, or to another pointer that jumps back — an infinite loop unless the parser explicitly guards against it


## Additional thoughts
> A format optimized for small size on the wire is often a format that's harder to parse safely. Space efficiency and parsing safety pull in opposite directions.
Every time a format introduces indirection, parsing becomes a graph traversal problem rather than a simple sequential read.

<br><br>