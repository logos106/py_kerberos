import struct

s = struct.Struct('! I I I 5s')
packed = s.pack(34, 56, 66, b'wertr')

s = struct.Struct('! I')
a = s.unpack(packed[0:4])[0]

# print(unpacked[0], unpacked[1], unpacked[2])
print(a)
