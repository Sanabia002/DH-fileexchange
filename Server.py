
import socket
import sys
import math

import pyDH
# device's IP address
HOST = "169.254.123.111"
PORT = 5001
with socket. socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        connection, address = s.accept ()

        with connection:
            print ("Connected by ", address)

            alice = pyDH.DiffieHellman(14)
            bob_pub_key_bytes = connection.recv (2048)
            bob_pub_key = int.from_bytes(bob_pub_key_bytes, sys.byteorder, signed=False)
            shared_key = alice.gen_shared_key(bob_pub_key)
            alice_pub_key = alice.gen_public_key()
            alice_pub_key_bytes = alice_pub_key.to_bytes(math.ceil(alice_pub_key.bit_length()/8), sys.byteorder, signed=False)
            connection.sendall (alice_pub_key_bytes)
            print (shared_key)
            received = client_socket.recv(BUFFER_SIZE).decode()
filename, filesize = received.split(SEPARATOR)
# remove absolute path if there is
filename = os.path.basename(filename)
# convert to integer
filesize = int(filesize)
# start receiving the file from the socket
# and writing to the file stream
with open(filename, "wb") as f:
    while True:
        # read 1024 bytes from the socket (receive)
        bytes_read = client_socket.recv(BUFFER_SIZE)
        if not bytes_read:    
            # nothing is received
            # file transmitting is done
            break
        # write to the file the bytes we just received
        f.write(bytes_read)
        # update the progress bar
        f = alice
with open('cipher.txt', 'rb') as encrypted_file: 
    encrypted = encrypted_file.read()
    decrypted = f.decrypt(encrypted)
with open('dec_plaintext.txt', 'wb') as decrypted_file:
    decrypted_file.write(decrypted)