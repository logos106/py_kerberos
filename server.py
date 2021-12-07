from datetime import datetime
import socket
import struct
from Crypto.Cipher import AES
import binascii
import os

HOST_SS = '127.0.0.1'  # The service server's hostname or IP address
PORT_SS = 65431        # The port used by the service server

MAX_LEN = 1024

FMT_AP_REQ          = '! 129s 65s'
FMT_TKT             = '! 16s 36s I 36s I I'
FMT_AP_RES          = '! I'
FMT_APP_DATA_REQ    = '! I'
FMT_AUTHENTICATOR   = '! 36s I I'

# ServerID
server_id = b'1a1acb43-6bd6-4a26-9ab8-519c7aa08cba'

# Sever key
ks = binascii.unhexlify('2261ECB5ED5D6BAF8D7A7068B28DCC8E')

def encrypt(key, plain):
    IV = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV=IV)

    pad_len = 16 - len(plain) % 16
    if pad_len < 16:
        plain = plain + str.encode(''.join([chr(32) for i in range(pad_len)]))
    cipher = encryptor.encrypt(plain)

    return IV + str.encode(chr(pad_len)) + cipher

def decrypt(key, cipher):
    IV = cipher[:16]
    print(len(cipher), len(cipher[17:]))
    encryptor = AES.new(key, AES.MODE_CBC, IV=IV)
    plain = encryptor.decrypt(cipher[17:])
    pad_len = int.from_bytes(cipher[16:17], "little")
    plain = plain[0:-pad_len]

    return plain

# Validate the AS_REQ message
def is_ap_req(message):
    s = struct.Struct(FMT_AP_REQ)
    try:
        unpacked = s.unpack(message)
        return True
    except Exception as e:
        return False

def is_app_data_req(message):
    s = struct.Struct(FMT_APP_DATA_REQ)
    try:
        unpacked = s.unpack(message)
        return True
    except Exception as e:
        return False

# Main function
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST_SS, PORT_SS))
        while True:
            data = sock.recvfrom(MAX_LEN)
            print(data)
            message = data[0]
            address = data[1]

            # If exit message
            if message == b'exit':
                s.sendto(b'I am quiting', address)
                break

            # If AP_REQ, then send AP_RES
            if is_ap_req(message):
                # Unpack the AP_REQ
                s = struct.Struct(FMT_AP_REQ)
                unpacked = s.unpack(message)

                # Decrypt Tkt with Ks to get Kcs
                tkt_pack = decrypt(ks, unpacked[0])
                s = struct.Struct(FMT_TKT)
                print('tkt_len', len(tkt_pack))
                tkt = s.unpack(tkt_pack)
                kcs = tkt[0]
                print('kcs@server', binascii.hexlify(kcs))

                # Decrypt Authenticator with Kcs to get timestamp3
                auth_pack = decrypt(kcs, unpacked[1])
                s = struct.Struct(FMT_AUTHENTICATOR)
                auth = s.unpack(auth_pack)
                timestamp3 = auth[2]

                # Send AP_RES message for response
                s = struct.Struct(FMT_AP_RES)
                res_pack = s.pack(timestamp3 + 1)
                res_enc = encrypt(kcs, res_pack)

                sock.sendto(res_enc, address)
            if is_app_data_req(message):
                pass
            else:
                sock.sendto(b'unknown', address)

if __name__ == "__main__":
    main()
