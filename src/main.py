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
     get_protocol,
     matches_filter
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

            packets=[]
            packet_number = 1

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
                    protocol = get_protocol(layers)

                    if not matches_filter(layers, filter_protocol, filter_port):
                        packet_number+=1
                        continue

                    print(f"Packet {packet_number}")
                    print("-" * 30)
    
                    for key, value in format_packet_record(packet):
                        print(f"{key:<20}: {value}")
                    print()
                    print()

                    print(summarize_packet(layers))
                    print()

                    for layer in layers:

                        if type(layer).__name__ == "EthernetFrame":
                            fields = format_ethernet(layer)

                        elif type(layer).__name__ == "IPv4Packet":
                            fields = format_ipv4(layer)

                        elif type(layer).__name__ == "UDPSegment":
                            fields = format_udp(layer)

                        elif type(layer).__name__ == "TCPSegment":
                            fields = format_tcp(layer)

                        else:
                            continue

                        for key, value in fields:
                            print(f"{key:<20}: {value}")

                        print()

                    if p_constants.DEBUG:
                        time.sleep(3)
                
                packet_number += 1
                
            print(f"Finished reading {packet_number - 1} packets.")

    except FileNotFoundError:
        print("Error: The requested file could not be found.")

    except PermissionError:
        print("Error: You do not have the required permissions to access this file.")

    except OSError as e:
        print(f"System Error encountered: {e}")

    except Exception as e:
        print(f"Unexpected Error: {e}")