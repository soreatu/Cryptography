# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2020-12-01)

'''
Implementation of TEA, a Tiny Encryption Algorithm.
'''

# Reference: http://www.cix.co.uk/~klockstone/tea.pdf


class TEA():
    def __init__(self, k):
        if not isinstance(k, bytes) and not isinstance(k, bytearray):
            raise TypeError("Type of key must be bytes/bytearray.")
        if len(k) != 16:
            raise ValueError("Length of key must be 16.")

        self.keys = []
        for i in range(0, 16, 4):
            (self.keys).append(int.from_bytes(k[i:i+4], 'big'))


    def encrypt(self, m):
        if not isinstance(m, bytes) and not isinstance(m, bytearray):
            raise TypeError("Type of message must be bytes/bytearray.")
        if len(m) != 8:
            raise ValueError("Length of message must be 8.")

        delta = 0x9e3779b9
        s = 0
        y = int.from_bytes(m[0:4], 'big')
        z = int.from_bytes(m[4:8], 'big')
        for _ in range(32):
            s = s + delta & 0xFFFFFFFF
            y = y + (((z<<4) + self.keys[0]) ^ (z+s) ^ ((z>>5) + self.keys[1])) & 0xFFFFFFFF
            z = z + (((y<<4) + self.keys[2]) ^ (y+s) ^ ((y>>5) + self.keys[3])) & 0xFFFFFFFF
        return b"".join(int.to_bytes(i, 4, 'big') for i in (y,z))

    def decrypt(self, c):
        if not isinstance(c, bytes) and not isinstance(c, bytearray):
            raise TypeError("Type of cipher must be bytes/bytearray.")
        if len(c) != 8:
            raise ValueError("Length of cipher must be 8.")

        delta = 0x9e3779b9
        s = (0x9e3779b9<<5) & 0xFFFFFFFF
        y = int.from_bytes(c[0:4], 'big')
        z = int.from_bytes(c[4:8], 'big')
        for _ in range(32):
            z = z - (((y<<4) + self.keys[2]) ^ (y+s) ^ ((y>>5) + self.keys[3])) & 0xFFFFFFFF
            y = y - (((z<<4) + self.keys[0]) ^ (z+s) ^ ((z>>5) + self.keys[1])) & 0xFFFFFFFF
            s = s - delta & 0xFFFFFFFF
        return b"".join(int.to_bytes(i, 4, 'big') for i in (y,z))



if __name__ == "__main__":
    key = bytes(range(16))
    msg = b"abcdefgh"

    tea = TEA(key)
    cipher = tea.encrypt(msg)
    decrypted = tea.decrypt(cipher)

    assert decrypted == msg
    print(f"key: {key}\nmsg: {msg}\ncipher:{cipher}\ndecrypted: {decrypted}")
