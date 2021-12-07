from datetime import datetime
import socket
import struct
from Crypto.Cipher import AES
import binascii
import os

HOST_AS = '127.0.0.1'  # The authentication server's hostname or IP address
PORT_AS = 65432        # The port used by the authentication server

HOST_SS = '127.0.0.1'  # The service server's hostname or IP address
PORT_SS = 65431        # The port used by the service server

MAX_LEN = 1024

FMT_AS_REQ          = '! 36s 36s I'
FMT_AUTHENTICATOR   = '! 36s I I'
FMT_AP_REQ          = '! 129s 65s'
FMT_AS_RES          = '! 16s 36s 36s I I 129s'
FMT_APP_DATA_REQ    = '! I 9s'

APP_DATA_REQUEST = 12345
APP_DATA         = 1234
TERMINATE        = 5555

# ClientID
client_id = b'b0c6fe2a-72d4-4e02-a389-8243f2c7143c'

# ServerID
server_id = b'1a1acb43-6bd6-4a26-9ab8-519c7aa08cba'

# Client key
kc = binascii.unhexlify('1F61ECB5ED5D6BAF8D7A7068B28DCC8E')

# Output file path
out_fpath = 'output.pdf'

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
    encryptor = AES.new(key, AES.MODE_CBC, IV=IV)
    plain = encryptor.decrypt(cipher[17:])
    pad_len = int.from_bytes(cipher[16:17], "little")
    plain = plain[0:-pad_len]

    return plain

def convert_ip_int(ip):
    return sum([int(ipField) << 8*index for index, ipField in enumerate(reversed(ip.split('.')))])

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Send AS_REQ message to authentication server
        curr_dt = datetime.now()
        timestamp1 = int(round(curr_dt.timestamp()))

        message1 = (client_id, server_id, timestamp1)
        s = struct.Struct(FMT_AS_REQ)
        msg_pack = s.pack(*message1)

        sock.sendto(msg_pack, (HOST_AS, PORT_AS))

        # Receive AS_RES message
        response1 = sock.recvfrom(MAX_LEN)

        # Decrypt AS_RES message with Kc
        decrypted = decrypt(kc, response1[0])

        # Unpack the response  to get the Kcs and Tkt
        s = struct.Struct(FMT_AS_RES)
        unpacked = s.unpack(decrypted)
        kcs = unpacked[0]
        tkt = unpacked[5]

        # Compose Authenticator and encrypt with Kcs
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        client_ip = convert_ip_int(local_ip)

        curr_dt = datetime.now()
        timestamp3 = int(round(curr_dt.timestamp()))

        auth = (client_id, client_ip, timestamp3)
        s = struct.Struct(FMT_AUTHENTICATOR)
        auth_pack = s.pack(*auth)
        auth_enc = encrypt(kcs, auth_pack)

        # Send AP_REQ message to server
        message2 = (tkt, auth_enc)
        s = struct.Struct(FMT_AP_REQ)
        msg_pack = s.pack(*message2)

        sock.sendto(msg_pack, (HOST_SS, PORT_SS))

        # Receive AP_RES message
        response2 = sock.recvfrom(MAX_LEN)
        decrypted = decrypt(kc, response2[0])
        timestamp = int.from_bytes(decrypted, "little")
        dt_object = datetime.fromtimestamp(timestamp)

        # Send APP_DATA_REQUEST message to server
        message3 = (APP_DATA_REQUEST, b'body-data')
        s = struct.Struct(FMT_APP_DATA_REQ)
        packet = s.pack(*message3)
        enc_pack = encrypt(kcs, packet)

        sock.sendto(enc_pack, (HOST_SS, PORT_SS))

        # Receive APP_DATA packet and decrypt
        response3 = sock.recvfrom(MAX_LEN)
        resp_dec = decrypt(kcs, response3[0])

        if (resp_dec == b'Unknown request'):
            print('Unknown request type')
            return

        s = struct.Struct('! I I')
        type, len = s.unpack(resp_dec[0:8])

        if type == APP_DATA:
            f = open(out_fpath, 'wb')

        while type == APP_DATA:
            s = struct.Struct('! I I ' + '{}s'.format(len))
            _, _, chunk = s.unpack(resp_dec)
            f.write(chunk)

            response3 = sock.recvfrom(MAX_LEN)
            resp_dec = decrypt(kcs, response3[0])

            s = struct.Struct('! I I')
            type, len = s.unpack(resp_dec[0:8])

        # TERMINATE packet
        if type == TERMINATE:
            s = struct.Struct('! I I')
            _, crcvalue = s.unpack(resp_dec[0:8])

            f.close()

    # print('Received', repr(data))

if __name__ == "__main__":
    main()
