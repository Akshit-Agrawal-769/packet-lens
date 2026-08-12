import os
import time
import p_constants
from pcap import (
    parse_global_header,
    format_global_header,
    parse_packet_record,
    format_packet_record,
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

            # Read Global Header
            data = f.read(p_constants.HEADER_SIZE)

            if len(data) < p_constants.HEADER_SIZE:
                print("Invalid or incomplete PCAP file.")
                continue

            print(f"Successfully opened {filepath}")

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
                
                print(f"Packet {packet_number}")
                print("-" * 30)

                for key, value in format_packet_record(packet):
                    print(f"{key:<20}: {value}")

                packet_data = f.read(packet.captured_length)
                print()
                print(header.linktype)
                print()
                print(packet_data.hex())
                time.sleep(4)

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