from datetime import datetime
import struct
import socket
from Crypto.Cipher import AES
import binascii
import os

HOST_AS = '127.0.0.1'  # The service server's hostname or IP address
PORT_AS = 65432        # The port used by the service server

MAX_LEN = 1024

FMT_AS_REQ  = '! 36s 36s I'
FMT_TKT     = '! 16s 36s I 36s I I'
FMT_AS_RES  = '! 16s 36s 36s I I 129s'

# Client key
kc = binascii.unhexlify('1F61ECB5ED5D6BAF8D7A7068B28DCC8E')

# Sever key
ks = binascii.unhexlify('2261ECB5ED5D6BAF8D7A7068B28DCC8E')

# Client-Sever key
kcs = binascii.unhexlify('3361ECB5ED5D6BAF8D7A7068B28DCC8E')

# AES-128 encrypt
def encrypt(key, plain):
    IV = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV=IV)

    pad_len = 16 - len(plain) % 16
    if pad_len < 16:
        plain = plain + str.encode(''.join([chr(32) for i in range(pad_len)]))
    cipher = encryptor.encrypt(plain)

    return IV + str.encode(chr(pad_len)) + cipher

# Convert ip address into integer
def convert_ip_int(ip):
    return sum([int(ipField) << 8*index for index, ipField in enumerate(reversed(ip.split('.')))])

# Validate the AS_REQ message
def is_as_req(message):
    s = struct.Struct(FMT_AS_REQ)
    try:
        unpacked = s.unpack(message)
        return True
    except Exception as e:
        return False

# Compose AS_RES message
def compose_as_res(data):
    # Unpack the AS_REQ
    s = struct.Struct(FMT_AS_REQ)
    unpacked = s.unpack(data[0])

    client_id = unpacked[0]
    server_id = unpacked[1]
    client_ip = convert_ip_int(data[1][0])
    curr_dt = datetime.now()
    timestamp2 = int(round(curr_dt.timestamp()))
    lifetime2 = 2

    # Compose Tkt and encrypt with Ks
    tkt = (kcs, client_id, client_ip, server_id, timestamp2, lifetime2)
    s = struct.Struct(FMT_TKT)
    tkt_pack = s.pack(*tkt)
    tkt_enc = encrypt(ks, tkt_pack)

    # Compose the message and encrypt with Kc
    message = (kcs, client_id, server_id, timestamp2, lifetime2, tkt_enc)
    s = struct.Struct(FMT_AS_RES)
    msg_pack = s.pack(*message)
    msg_enc = encrypt(kc, msg_pack)

    return msg_enc


def main():
    # Listen for the connection
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST_AS, PORT_AS))
        while True:
            data = sock.recvfrom(MAX_LEN)
            print(data)
            message = data[0]
            address = data[1]

            if message == b'exit':
                s.sendto(b'I am quiting', address)
                break

            # If AS_REQ, then send AS_RES
            if is_as_req(message):
                # Compose AS_RES message for response
                response = compose_as_res(data)
                sock.sendto(response, address)
            else:
                sock.sendto(b'unknown', address)

    # Send AS_REQ message to authentication server

if __name__ == "__main__":
    main()