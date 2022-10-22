import socket
import math
import sys
import os
import cryptography
import pyDH
import threading
from cryptography.fernet import Fernet
HOST = "169.254.123.111"
PORT = 5001
with socket. socket (socket.AF_INET, socket.SOCK_STREAM) as s:
    s. connect ((HOST, PORT))

    bob = pyDH.DiffieHellman(14)
    bob_pub_key = bob.gen_public_key()
    bob_pub_key_bytes = bob_pub_key.to_bytes(math.ceil (bob_pub_key.bit_length()/8), sys.byteorder, signed=False)
    s.sendall (bob_pub_key_bytes)
    alice_pub_key_bytes = s.recv(2048)
    alice_pub_key = int.from_bytes (alice_pub_key_bytes, sys.byteorder, signed=False)
    Shared_key = bob.gen_shared_key(alice_pub_key)
    print (Shared_key)
    f = alice_pub_key

    with open('plaintext.txt', 'rb') as original_file:
        original = original_file.read()

    encrypted = f.encrypt(original)

    with open ('cipher.txt', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    filename = "cipher.txt"
    # get the file size
    filesize = os.path.getsize(filename)
    s.send(f"{filename}{SEPARATOR}{filesize}".encode())
    with open(filename, "rb") as f:
        while True:
         # read the bytes from the file
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
            # file transmitting is done
                break
        # we use sendall to assure transimission in 
        # busy networks
        s.sendall(bytes_read)
