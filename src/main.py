import os
import time
import p_constants
from pcap import parse_global_header,format_global_header

while True:

    choice = input('continue? y/n ').strip().lower()
    if choice=='n':
        break  
    filepath=input('file path: ')
    if not os.path.isfile(filepath):
        print("File not found.")
        continue

    try:
        with open(filepath,'rb') as f:
            data= f.read(p_constants.HEADER_SIZE)

    except FileNotFoundError:
        print("Error: The requested file could not be found.")
    except PermissionError:
        print("Error: You do not have the required permissions to access this file.")
    except OSError as e:
        print(f"System Error encountered: {e}")

    else:
        if len(data) < p_constants.HEADER_SIZE:
            print("Invalid or incomplete PCAP file.")
            continue
        print(f"Successfully opened {filepath}")
        
        print('Commencing operation')
        time.sleep(1)
        print('1')
        time.sleep(1)
        print('2')
        time.sleep(1)
        print('3')
        time.sleep(1)

        print("Global Header:")
        for i, byte in enumerate(data):
            print(f"Byte {i:02}: {byte:02X}")

        print("=" * 40)
        print("PacketLens")
        print("=" * 40)

        header=parse_global_header(data)
        for key, value in format_global_header(header):
            print(f"{key:<15}: {value}")