import binascii


ks = binascii.unhexlify('2261ECB5ED5D6BAF8D7A7068B28DCC8E')
print(ks)
dd = binascii.hexlify(ks)
print(dd)
