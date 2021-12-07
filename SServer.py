from datetime import datetime
import socket
from struct import pack, unpack
from Crypto.Cipher import AES
import binascii
import os

HOST_SS = '127.0.0.1'  # The service server's hostname or IP address
PORT_SS = 65431        # The port used by the service server

# ServerID
server_id = b'1a1acb43-6bd6-4a26-9ab8-519c7aa08cba'

# Sever key
ks = binascii.unhexlify('2261ECB5ED5D6BAF8D7A7068B28DCC8E')

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind((HOST_SS, PORT_SS))
    while True:
        data = sock.recvfrom(1024)
        print(data)
        message = data[0]
        address = data[1]

        # If exit message
        if message == b'exit':
            s.sendto(b'I am quiting', address)
            break


        if message == b'ap_req':
            sock.sendto(message, address)
        else:
            sock.sendto(b'unknown', address)
