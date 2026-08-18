import os
import time
import p_constants
from pcap import (
    parse_global_header,
    format_global_header,
    parse_packet_record,
    format_packet_record,
    format_ethernet,
    format_ipv4,
    format_udp,
    format_tcp
)
from parser import (
     parse_packet,
     summarize_packet,
     matches_filter
     )

from models import (
    GlobalHeader, 
    PacketRecord, 
    EthernetFrame, 
    IPv4Packet, 
    UDPSegment, 
    TCPSegment
    )

while True:

    choice = input("continue? y/n ").strip().lower()
    if choice == "n":
        break

    filepath = input("file path: ")

    if not os.path.isfile(filepath):
        print("File not found.")
        continue

    try:
        with open(filepath, "rb") as f:

            filter_protocol = input("Filter (all/tcp/udp): ").strip().lower()
            if filter_protocol not in ("all", "tcp", "udp"):
                print("Invalid filter.")
                continue
            filter_port = input("Port filter (leave empty for any): ").strip()
            if filter_port == "":
                filter_port = None
            else:
                try:
                    filter_port = int(filter_port)

                    if not 0 <= filter_port <= 65535:
                        print('Invalid port ')
                        continue

                except ValueError:
                    print('give a number -_- ')
                    continue

            # Read Global Header
            data = f.read(p_constants.HEADER_SIZE)

            if len(data) < p_constants.HEADER_SIZE:
                print("Invalid or incomplete PCAP file.")
                continue

            print(f"Successfully opened {filepath}")

            if p_constants.DEBUG:
                print("Commencing operation")
                time.sleep(1)
                print("1")
                time.sleep(1)
                print("2")
                time.sleep(1)
                print("3")
                time.sleep(1)

            print("\nGlobal Header:")


            p_constants.print_banner()

            header = parse_global_header(data)
            if p_constants.DEBUG:
                for key, value in format_global_header(header):
                    print(f"{key:<20}: {value}")

            print()

            matched_packets=[]
            packet_number = 1


            print()
            print(
                f"{'No.':<6}"
                f"{'Time':<18}"
                f"{'Protocol':<10}"
                f"{'Source':<25}"
                f"{'Destination':<25}"
                f"{'Length':<8}"
                f"{'Info'}"
            )

            print("-" * 110)

            while True:

                packet_header = f.read(
                    p_constants.PACKET_RECORD_HEADER_SIZE
                )

                # EOF reached
                if not packet_header:
                    break

                # Safety check
                if len(packet_header) < p_constants.PACKET_RECORD_HEADER_SIZE:
                    print("Incomplete packet record header.")
                    break

                packet = parse_packet_record(
                    packet_header,
                    header.endianness,
                )

                packet_data = f.read(packet.captured_length)

                if len(packet_data) < packet.captured_length:
                    print("Incomplete packet data.")
                    break
                
                if header.linktype == 1:

                    layers = parse_packet(packet_data)

                    if not matches_filter(layers, filter_protocol, filter_port):
                        packet_number+=1
                        continue

                    matched_packets.append(
                    (packet_number, packet, layers))

                    timestamp = (
                    packet.timestamp_seconds
                    + packet.timestamp_microseconds / 1_000_000)

                    summary = summarize_packet(layers)
                    print(
                        f'{packet_number:<6}'
                        f'{timestamp:<18.6f}'
                        f'{summary['protocol']:<10}'
                        f'{summary['source']:<25}'
                        f'{summary['destination']:<25}'
                        f'{packet.captured_length:<8}'
                        f'{summary['info']}'
                    )

                    if p_constants.DEBUG:
                        time.sleep(1)
                
                packet_number += 1

            while True:

                choice = input(
                    "\nEnter packet number for details "
                    "(or press Enter to continue): ").strip()

                if choice == "":
                    break

                try:
                    selected_number = int(choice)
                except ValueError:
                    print("Give me a packet number -_-")
                    continue

                selected_packet = None

                for number, packet, layers in matched_packets:
                    if number == selected_number:
                        selected_packet = (packet, layers)
                        break

                if selected_packet is None:
                    print("That packet isn't in the displayed results.")
                    continue

                packet, layers = selected_packet

                print()
                print("=" * 50)
                print(f"Packet {selected_number}")
                print("=" * 50)

                print("\nPacket Record")
                print("-" * 30)

                for key, value in format_packet_record(packet):
                    print(f"{key:<25}: {value}")

                print()

                for layer in layers:

                    if isinstance(layer, EthernetFrame):
                        fields = format_ethernet(layer)

                    elif isinstance(layer, IPv4Packet):
                        fields = format_ipv4(layer)

                    elif isinstance(layer, UDPSegment):
                        fields = format_udp(layer)

                    elif isinstance(layer, TCPSegment):
                        fields = format_tcp(layer)
                    else:
                        continue

                    print(type(layer).__name__)
                    print("-" * 30)

                    for key, value in fields:
                        print(f"{key:<25}: {value}")

                    print()
            
            print(f"Finished reading {packet_number - 1} packets.")

    except FileNotFoundError:
        print("Error: The requested file could not be found.")

    except PermissionError:
        print("Error: You do not have the required permissions to access this file.")

    except OSError as e:
        print(f"System Error encountered: {e}")

    except Exception as e:
        print(f"Unexpected Error: {e}")