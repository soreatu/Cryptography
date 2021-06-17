# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2020-09-19)

'''
SM3 Hash Function Implementation.
'''

# Reference: http://www.sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf

__all__ = [
    'SM3'
]

class SM3():
    def __init__(self, m=b""):
        """Returns a SM3 hash object; optionally initialized with some bytes.

        Args:
            m (bytes, optional): bytes-like object to initialize the hash
                object. Defaults to b"".

        Raises:
            TypeError: m is not a bytes-like object
        """
        self._V = SM3._IV.copy()     # V: 256-bit states
        self._m = m                  # uncompresed bytes
        self._length = len(self._m)  # total length
        # no initialization value
        if m == None:
            return
        # given initialization value
        if not isinstance(m, (bytes, bytearray)):
            raise TypeError(f"a bytes-like object is required, not '{type(m)}'")
        # compress those already fill in a 512-bit block.
        for i in range(len(m) // 64):
            self._V = SM3._one_block(self._V, m[i*64:(i+1)*64])
        # record the left uncompressed bytes (< 512-bit)
        left_length = len(m) % 64
        if left_length > 0:
            self._m = m[-left_length:]
        else:
            self._m = b""

    def update(self, m):
        """Update this hash object's state with the provided bytes.

        Args:
            m (bytes): bytes-like object to update the hash object.
        """
        self._m += m
        self._length += len(m)
        # compress those which can already fill in 512-bit block.
        for i in range(len(self._m) // 64):
            self._V = SM3._one_block(self._V, self._m[i*64:(i+1)*64])
        # record the left bytes (< 512-bit)
        left_length = len(self._m) % 64
        if left_length > 0:
            self._m = self._m[-left_length:]
        else:
            self._m = b""

    def digest(self):
        """Return the digest value as a bytes object.
        """
        padded = SM3._pad(self._m, self._length)
        for i in range(len(padded)//64):
            V = SM3._one_block(self._V, padded[i*64:(i+1)*64])
        return SM3._words_to_bytes(V)

    def hexdigest(self):
        """Return the digest value as a string of hexadecimal digits.
        """
        return self.digest().hex()

    @staticmethod
    def _one_block(V, B):
        """Perform the one block compress function.

        Args:
            V (list): 8-word list
            B (bytes): (512-bit bytes) block

        Returns:
            list: 8-word list after compressing
        """
        W, WW = SM3._ME(B)
        return SM3._CF(V, W, WW)

    @staticmethod
    def _ME(B):
        """Message expansion, (512-bit bytes) block -> 132-word list.

        Args:
            B (bytes): 512-bit bytes block

        Returns:
            list, list: 68-word list W, 64-word list WW
        """
        W  = SM3._bytes_to_words(B) + [0]*52
        WW = [0] * 64
        for j in range(16, 68):
            W[j] = SM3._P1(W[j-16] ^ W[j-9] ^ SM3._rol(W[j-3], 15)) \
                   ^ SM3._rol(W[j-13], 7) ^ W[j-6]
        for j in range(64):
            WW[j] = W[j] ^ W[j+4]
        return W, WW

    @staticmethod
    def _CF(V, W, WW):
        """Compress function, 64 rounds, `V_i+1 = CF(V_i, B_i)`

        Args:
            V (list): 8-word list V_i
            W (list): 68-word list W
            WW (list): 64-word list W'

        Returns:
            list: 8-word list V_i+1
        """
        A, B, C, D, E, F, G, H = V
        for j in range(64):
            SS1 = SM3._rol(
                (SM3._rol(A, 12) + E + SM3._rol(SM3._T(j), j%32)) & 0xFFFFFFFF, 7
            )
            SS2 = SS1 ^ SM3._rol(A, 12)
            TT1 = (SM3._FF(A, B, C, j) + D + SS2 + WW[j]) & 0xFFFFFFFF
            TT2 = (SM3._GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = SM3._rol(B, 9)
            B = A
            A = TT1
            H = G
            G = SM3._rol(F, 19)
            F = E
            E = SM3._P0(TT2)
        return [A^V[0], B^V[1], C^V[2], D^V[3], E^V[4], F^V[5], G^V[6], H^V[7]]

    @staticmethod
    def _pad(m, total_length):
        """Padding the left bytes up to 512-bit.

        Args:
            m (bytes): the left bytes
            total_length (int): the accumulated length

        Returns:
            bytes: 512-bit bytes after padding
        """
        left_length = len(m) * 8
        k = (447 - left_length) % 512
        pad = int("1" + "0"*k, 2).to_bytes((k+1) // 8, 'big')  # "1" + "00...00"
        pad += (total_length*8).to_bytes(8, 'big')             # 64-bit length
        return m + pad

    @staticmethod
    def _bytes_to_words(b):
        """Convert byte sequence to word list, 4 bytes => 1 word.

        Args:
            b (bytes): byte sequence

        Returns:
            list: word list
        """
        res = []
        for i in range(0, len(b), 4):
            res.append(int.from_bytes(b[i:i+4], 'big'))
        return res

    @staticmethod
    def _words_to_bytes(w):
        """Convert word list to byte sequence, 1 word => 4 bytes.

        Args:
            w (list): word list

        Returns:
            bytes: bytes sequence
        """
        return b"".join(int.to_bytes(i, 4, 'big') for i in w)

    @staticmethod
    def _rol(i, shift):
        """Recusive left shift of a 32-bit word.

        Args:
            i (int): the input 32-bit word
            shift (int): how much to shift

        Returns:
            int: the shifted result
        """
        return (i << shift) & 0xFFFFFFFF | (i >> (32-shift))

    @staticmethod
    def _P0(X):
        return X ^ SM3._rol(X, 9) ^ SM3._rol(X, 17)

    @staticmethod
    def _P1(X):
        return X ^ SM3._rol(X, 15) ^ SM3._rol(X, 23)

    @staticmethod
    def _T(j):
        if 0 <= j <= 15:
            return 0x79cc4519
        elif 16 <= j <= 63:
            return 0x7a879d8a
        else:
            raise ValueError(f"undefined value: {j}")

    @staticmethod
    def _FF(X, Y, Z, j):
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        elif 16 <= j <= 63:
            return (X & Y) | (X & Z) | (Y & Z)
        else:
            raise ValueError(f"undefined value: {j}")

    @staticmethod
    def _GG(X, Y, Z, j):
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        elif 16 <= j <= 63:
            return (X & Y) | ((X ^ 0xFFFFFFFF) & Z)
        else:
            raise ValueError(f"undefined value: {j}")

    _IV = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]


def test1():
    print(f"SM3(b'abc'): {SM3(b'abc').hexdigest()}")
    # 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

def test2():
    print(f"SM3(b'abcd'*16): {SM3(b'abcd'*16).hexdigest()}")
    # debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732

if __name__ == "__main__":
    test1()
    test2()