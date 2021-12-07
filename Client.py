from datetime import datetime
import socket
from struct import pack, unpack
from Crypto.Cipher import AES
import binascii
import os

HOST_AS = '127.0.0.1'  # The authentication server's hostname or IP address
PORT_AS = 65432        # The port used by the authentication server

HOST_SS = '127.0.0.1'  # The service server's hostname or IP address
PORT_SS = 65431        # The port used by the service server

# ClientID
client_id = b'b0c6fe2a-72d4-4e02-a389-8243f2c7143c'

# ServerID
server_id = b'1a1acb43-6bd6-4a26-9ab8-519c7aa08cba'

# Current time
curr_dt = datetime.now()
timestamp = int(round(curr_dt.timestamp()))

# Client key
kc = binascii.unhexlify('1F61ECB5ED5D6BAF8D7A7068B28DCC8E')

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
    pad_len = cipher[16:17]
    encryptor = AES.new(key, AES.MODE_CBC, IV=IV)
    plain = encryptor.decrypt(cipher[17:])
    pad_len = int.from_bytes(pad_len, "little")
    plain = plain[0:-pad_len]

    return plain

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    # Send AS_REQ message to authentication server
    message = (client_id, server_id, timestamp)
    msg_pack = pack('! 36s 36s I', *message)
    sock.sendto(msg_pack, (HOST_AS, PORT_AS))

    # Receive
    data = sock.recvfrom(1024)
print('Received', repr(data))
