# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2020-09-19)

'''
SM4 Symmetric Cipher Implementation.
'''

# Reference: http://www.gmbz.org.cn/main/viewfile/20180108015408199368.html

__all__ = [
    'SM4'
]

class SM4():
    def __init__(self, key):
        """Initialize the 32 round keys, given a 16-byte master key.

        Args:
            key (bytes): 16-byte master key.

        Raises:
            TypeError: key is not a bytes-like object
            ValueError: length of key is not 16
        """
        self.rks = SM4._key_expansion(key)

    def encrypt(self, msg):
        """Encryption of SM4 cipher, (16 bytes) msg => (16 bytes) cipher.

        Args:
            msg (bytes): the message to be encrypted

        Raises:
            TypeError: msg is not a bytes-like object
            ValueError: length of msg is not 16.

        Returns:
            bytes: the cipher after encryption
        """
        return self._encrypt(msg, enc=True)

    def decrypt(self, cipher):
        """Decryption of SM4 cipher, (16 bytes) cipher => (16 bytes) msg.

        Args:
            msg (bytes): the cipher to be decrypted

        Raises:
            TypeError: cipher is not a bytes-like object
            ValueError: length of cipher is not 16.

        Returns:
            bytes: the msg after decryption
        """
        return self._encrypt(cipher, enc=False)

    def _encrypt(self, msg, enc=True):
        # basic check
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError(f"a bytes-like object is required, not '{type(msg)}'")
        if len(msg) != 16:
            raise ValueError(f"the length must be 16, not '{len(msg)}'")
        # X: list that represents all the 36 intermediate state words
        X = SM4._bytes_to_words(msg) + [0]*32
        for i in range(32):
            if enc:
                X[i+4] = X[i] ^ SM4._T(X[i+1], X[i+2], X[i+3], self.rks[i])
            else:
                X[i+4] = X[i] ^ SM4._T(X[i+1], X[i+2], X[i+3], self.rks[-i-1])
        # last 4 words is the final result
        return SM4._words_to_bytes(X[-1:-5:-1])


    @staticmethod
    def _key_expansion(key):
        """Generate the 32 round keys given the master key.

        Args:
            key (bytes): the master key

        Raises:
            TypeError: key is not a bytes-like object
            ValueError: length of key is not 16

        Returns:
            list: the 32 round keys
        """
        # basic check
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError(f"a bytes-like object is required, not '{type(key)}'")
        if len(key) != 16:
            raise ValueError(f"length of key must be 16, not '{len(key)}'")
        # K: list that represents all the 36 key words
        K = [k ^ SM4._FK[i] for i, k in enumerate(SM4._bytes_to_words(key))] + [0]*32
        for i in range(32):
                K[i+4] = K[i] ^ SM4._TT(K[i+1], K[i+2], K[i+3], SM4._CK[i])
        # all words except for the first 4 are round keys
        return K[4:]


    @staticmethod
    def _T(a, b, c, rk):
        """Compound function T, (32-bit integer) word => (32-bit integer) word.

        Args:
            a (int): X_i+1
            b (int): X_i+2
            c (int): X_i+3
            rk (int): round key

        Returns:
            int: result of T function
        """
        return SM4._L(SM4._r(a ^ b ^ c ^ rk))

    @staticmethod
    def _TT(a, b, c, d):
        """Compound function T' for key expansion.

        Returns:
            int: result of T' function
        """
        return SM4._LL(SM4._r(a ^ b ^ c ^ d))

    @staticmethod
    def _r(A):
        """The non-linear function r, (32-bit integer) word => (32-bit integer) word.

        Args:
            A (int): the 32-bit input word

        Returns:
            int: the 32-bit output word
        """
        B = 0
        for byte in SM4._words_to_bytes([A]):
            B = (B << 8) + SM4._SBOX[byte]
        return B

    @staticmethod
    def _L(B):
        """The linear function L, (32-bit integer) word => (32-bit integer) word.

        Args:
            B (int): the 32-bit input word

        Returns:
            int: the 32-bit output word
        """
        return B ^ SM4._rol(B, 2) ^ SM4._rol(B, 10) ^ SM4._rol(B, 18) ^ SM4._rol(B, 24)

    @staticmethod
    def _LL(B):
        """The linear function L' for key expansion.

        Args:
            B (int): the 32-bit input word

        Returns:
            int: the 32-bit output word
        """
        return B ^ SM4._rol(B, 13) ^ SM4._rol(B, 23)

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

    _SBOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
        0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c,  0x5,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe,  0x4, 0xc3,
        0xaa, 0x44, 0x13, 0x26, 0x49, 0x86,  0x6, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
        0x33, 0x54,  0xb, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9,  0x8, 0xe8, 0x95,
        0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47,  0x7, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
        0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
        0xf8, 0xeb,  0xf, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24,  0xe, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
        0x25, 0x22, 0x7c, 0x3b,  0x1, 0x21, 0x78, 0x87,
        0xd4,  0x0, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
        0x4c, 0x36,  0x2, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
        0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
        0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
        0xc0, 0x29, 0x23, 0xab,  0xd, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
         0x3, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
        0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
         0xa, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
        0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a,  0xc, 0x96, 0x77, 0x7e,
        0x65, 0xb9, 0xf1,  0x9, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
        0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
    ]
    _FK = [
        0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
    ]
    _CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]


def test1():
    msg = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")

    sm4 = SM4(key)
    cipher = sm4.encrypt(msg)
    decrypted = sm4.decrypt(cipher)

    print(f"message: {msg.hex()}")
    print(f"cipher:  {cipher.hex()}")
    print(f"decrypted: {decrypted.hex()}")

def test2():
    msg = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")

    sm4 = SM4(key)
    from tqdm import tqdm
    for i in tqdm(range(1000000)):
        msg = sm4.encrypt(msg)
    print(f"Encrypt 1,000,000 times: {msg.hex()}")


if __name__ == "__main__":
    test1()
    test2()