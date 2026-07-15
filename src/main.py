import os
import time
from constants import *

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
            data= f.read(HEADER_SIZE)

    except FileNotFoundError:
        print("Error: The requested file could not be found.")
    except PermissionError:
        print("Error: You do not have the required permissions to access this file.")
    except OSError as e:
        print(f"System Error encountered: {e.strerror}")

    else:
        if len(data) < HEADER_SIZE:
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