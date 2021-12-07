from Crypto.Cipher import AES
import binascii
import os

kc = binascii.unhexlify('1F61ECB5ED5D6BAF8D7A7068B28DCC8E')

def encrypt(key, plain):
    IV = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV=IV)

    pad_len = 16 - len(plain) % 16
    if pad_len < 16:
        plain = plain + str.encode(''.join([chr(32) for i in range(pad_len)]))
    cipher = encryptor.encrypt(plain)

    return IV + str.encode(chr(pad_len)) + cipher

c = encrypt(kc, b'Hell0 World')
print(c, len(c))
