# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2021-06-16)

"""
SHA-1 Hash Function Implementation.
"""

# Reference: https://zh.wikipedia.org/wiki/SHA-1

__all__ = [
    'SHA1'
]


class SHA1(object):
    def __init__(self, m=b""):
        """Returns a SHA-1 hash object; optionally initialized with some bytes.

        Args:
            m (bytes, optional): bytes-like object to initialize the hash
                object. Defaults to b"".

        Raises:
            TypeError: m is not a bytes-like object
        """
        self._V = SHA1._IV.copy()       # V: 256-bit states
        self._m = m                     # uncompressed bytes
        self._length = len(self._m)     # total length
        self._h0, self._h1, self._h2, self._h3, self._h4 = self._IV
        # no initialization value
        if m is None:
            return
        # given initialization value
        if not isinstance(m, (bytes, bytearray)):
            raise TypeError(f"a bytes-like object is required, not '{type(m)}'")
        # compress those already fill in a 512-bit block.
        for i in range(len(m)//64):
            self._one_block(m[i*64:(i+1)*64])
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
            self._V = self._one_block(self._m[i*64:(i+1)*64])
        # record the left bytes (< 512-bit)
        left_length = len(self._m) % 64
        if left_length > 0:
            self._m = self._m[-left_length:]
        else:
            self._m = b""

    def digest(self):
        """Return the digest value as a bytes object.
        """
        padded = SHA1._pad(self._m, self._length)
        for i in range(len(padded)//64):
            self._one_block(padded[i*64:(i+1)*64])
        checksum = b""
        checksum += SHA1._word_to_bytes(self._h0)
        checksum += SHA1._word_to_bytes(self._h1)
        checksum += SHA1._word_to_bytes(self._h2)
        checksum += SHA1._word_to_bytes(self._h3)
        checksum += SHA1._word_to_bytes(self._h4)
        return checksum

    def hexdigest(self):
        """Return the digest value as a string of hexadecimal digits.
        """
        return self.digest().hex()

    def _one_block(self, chunk):
        """Perform the one block compress function.

        Args:
            chunk (bytes): (512-bit bytes) block
        """
        w = [0] * 80
        for i in range(0, len(chunk), 4):
            w[i//4] = SHA1._bytes_to_word(chunk[i:i+4])
        for i in range(16, 80):
            w[i] = SHA1._left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
        a, b, c, d, e = self._h0, self._h1, self._h2, self._h3, self._h4
        f, k = 0, 0

        for i in range(80):
            if 0 <= i <= 20:
                f = (b & c) | ((b ^ 0xFFFFFFFF) & d)
                k = 0x5A827999
            if 20 <= i <= 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            if 40 <= i <= 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            if 60 <= i <= 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = SHA1._u32(SHA1._left_rotate(a, 5) + f + e + k + w[i])
            a, b, c, d, e = temp, a, SHA1._left_rotate(b, 30), c, d

        self._h0 = SHA1._u32(self._h0 + a)
        self._h1 = SHA1._u32(self._h1 + b)
        self._h2 = SHA1._u32(self._h2 + c)
        self._h3 = SHA1._u32(self._h3 + d)
        self._h4 = SHA1._u32(self._h4 + e)

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
        pad = int("1" + "0" * k, 2).to_bytes((k + 1) // 8, 'big')  # "1" + "00...00"
        pad += (total_length * 8).to_bytes(8, 'big')  # 64-bit length
        return m + pad

    @staticmethod
    def _bytes_to_word(b):
        """Convert byte sequence to a word, 4 bytes => 1 word.

        Args:
            b (bytes): byte sequence

        Returns:
            int: a 32-bit word
        """
        return int.from_bytes(b[0:4], 'big')

    @staticmethod
    def _word_to_bytes(w):
        """Convert a word to byte sequence, 1 word => 4 bytes.

        Args:
            w (int): a 32-bit word

        Returns:
            bytes: bytes sequence
        """
        return w.to_bytes(4, 'big')

    @staticmethod
    def _left_rotate(i, shift):
        """Recursive left shift of a 32-bit word.

        Args:
            i (int): the input 32-bit word
            shift (int): bits to shift

        Returns:
            int: the shifted result
        """
        return SHA1._u32(i << shift) | (i >> (32 - shift))

    @staticmethod
    def _u32(i):
        return i & 0xFFFFFFFF

    _IV = [
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    ]


def test1():
    import hashlib
    print(f"hashlib.sha1(b'abc'): {hashlib.sha1(b'abc').hexdigest()}")
    print(f"SHA1(b'abc'): {SHA1(b'abc').hexdigest()}")
    # hashlib.sha1(b'abc'): a9993e364706816aba3e25717850c26c9cd0d89d
    # SHA1(b'abc'): a9993e364706816aba3e25717850c26c9cd0d89d


def test2():
    import hashlib
    print(f"hashlib.sha1(b'abc'*1000): {hashlib.sha1(b'abc'*1000).hexdigest()}")
    print(f"SHA1(b'abc'*1000): {SHA1(b'abc'*1000).hexdigest()}")
    # hashlib.sha1(b'abc'*1000): 053b4dd5a9642608cc0b599e96f491154b37b2c6
    # SHA1(b'abc'*1000): 053b4dd5a9642608cc0b599e96f491154b37b2c6


if __name__ == "__main__":
    test1()
    test2()
