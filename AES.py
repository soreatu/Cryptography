# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2021-06-16)

"""
AES (Advance Encryption Standard) implementation.
"""


# Reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf


class AES(object):
    def __init__(self, key):
        """
        Return a AES object for encryption or decryption

        :param key: 128-bit/196-bit/256-bit key bytes
        :raise AssertionError: if the type or length of key is invalid
        """
        assert isinstance(key, (bytes, bytearray)), f"type of key must be bytes or bytearray, not {type(key)}"
        assert len(key) == 16 or len(key) == 24 or len(key) == 32, f"key length must be 16, 24, or 32, not {len(key)}"
        self.key = key

        self.rounds = AES.number_of_rounds[len(key)]
        self.subkeys = AES.key_expansion(self.key, self.rounds)

    # encryption & decryption function
    def encrypt(self, msg):
        """
        Encryption of AES

        :param bytes msg: 128-bit bytes of plaintext
        :return: 128-bit bytes ciphertext
        :rtype: bytes
        """
        assert len(msg) == 16, f"block size is 16, input length is {len(msg)}"

        # start
        r = 0
        k_sch = self.subkeys[0] + self.subkeys[1] + self.subkeys[2] + self.subkeys[3]

        state = list(msg)
        AES.add_round_key(state, k_sch)

        # round 1 ~ `rounds`-1
        for r in range(1, self.rounds):
            AES.sub_bytes(state)
            AES.shift_rows(state)
            AES.mix_columns(state)
            k_sch = self.subkeys[4*r] + self.subkeys[4*r+1] + self.subkeys[4*r+2] + self.subkeys[4*r+3]
            AES.add_round_key(state, k_sch)

        # the last round
        r = self.rounds
        AES.sub_bytes(state)
        AES.shift_rows(state)
        k_sch = self.subkeys[-4] + self.subkeys[-3] + self.subkeys[-2] + self.subkeys[-1]
        AES.add_round_key(state, k_sch)

        # convert `list` state to `bytes` output
        output = bytes(state)
        return output

    def decrypt(self, cipher):
        """
        Decryption of AES

        :param bytes cipher: 128-bit bytes of ciphertext
        :return: 128-bit bytes plaintext
        :rtype: bytes
        """
        assert len(cipher) == 16, f"block size is 16, input length is {len(cipher)}"

        # start
        k_sch = self.subkeys[-4] + self.subkeys[-3] + self.subkeys[-2] + self.subkeys[-1]

        state = list(cipher)
        AES.add_round_key(state, k_sch)

        # round 1 ~ `rounds`-1
        for r in range(1, self.rounds):
            AES.inv_shift_rows(state)
            AES.inv_sub_bytes(state)
            k_sch = self.subkeys[-4*r-4] + self.subkeys[-4*r-3] + self.subkeys[-4*r-2] + self.subkeys[-4*r-1]
            AES.add_round_key(state, k_sch)
            AES.inv_mix_columns(state)

        # the last round
        r = self.rounds
        AES.inv_shift_rows(state)
        AES.inv_sub_bytes(state)
        k_sch = self.subkeys[0] + self.subkeys[1] + self.subkeys[2] + self.subkeys[3]
        AES.add_round_key(state, k_sch)

        # convert `list` state to `bytes` output
        output = bytes(state)
        return output

    # constant
    number_of_rounds = {16: 10, 24: 12, 32: 14}

    # table
    Sbox = (
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    )
    inv_Sbox = (
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    )
    Rcon = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # encryption & decryption layers
    @staticmethod
    def sub_bytes(s):
        """
        A non-linear substitution step where each byte is replaced with another according to a lookup table

        :param list s: 16-byte list of the state
        """
        for i in range(16):
            s[i] = AES.Sbox[s[i]]

    @staticmethod
    def inv_sub_bytes(s):
        """
        Inverse of SubBytes

        :param list s: 16-byte list of the state
        """
        for i in range(16):
            s[i] = AES.inv_Sbox[s[i]]

    @staticmethod
    def shift_rows(s):
        """
        A transposition step where the last three rows of the state are shifted cyclically a certain number of steps

        :param list s: 16-byte list of the state
        """
        s[:] = list(s[0::5] + s[4::5] + s[3:4:5] + s[8::5] + s[2:8:5] + s[12::5] + s[1:12:5])

    @staticmethod
    def inv_shift_rows(s):
        """
        Inverse of ShiftRows

        :param list s: 16-byte list of the state
        """
        s[:] = [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]]

    @staticmethod
    def mix_columns(s):
        """
        A linear mixing operation which operates on the columns of the state, combining the four bytes in each column

        :param list s: 16-byte list of the state
        :no return
        """

        # ref: https://github.com/bozhu/AES-Python/blob/master/aes.py
        def xtime(a):
            return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

        for i in range(4):
            t = s[4*i] ^ s[4*i+1] ^ s[4*i+2] ^ s[4*i+3]
            u = s[4*i]
            s[4*i] ^= t ^ xtime(s[4*i] ^ s[4*i+1])
            s[4*i+1] ^= t ^ xtime(s[4*i+1] ^ s[4*i+2])
            s[4*i+2] ^= t ^ xtime(s[4*i+2] ^ s[4*i+3])
            s[4*i+3] ^= t ^ xtime(s[4*i+3] ^ u)

    @staticmethod
    def inv_mix_columns(s):
        """
        Inverse of MixColumns

        :param list s: 16-byte list of the state
        """
        # fips-197 5.3.3
        for i in range(4):
            s[4*i], s[4*i+1], s[4*i+2], s[4*i+3] = \
                AES.gmul(0x0e, s[4*i]) ^ AES.gmul(0x0b, s[4*i+1]) ^ AES.gmul(0x0d, s[4*i+2]) ^ AES.gmul(0x09, s[4*i+3]), \
                AES.gmul(0x09, s[4*i]) ^ AES.gmul(0x0e, s[4*i+1]) ^ AES.gmul(0x0b, s[4*i+2]) ^ AES.gmul(0x0d, s[4*i+3]), \
                AES.gmul(0x0d, s[4*i]) ^ AES.gmul(0x09, s[4*i+1]) ^ AES.gmul(0x0e, s[4*i+2]) ^ AES.gmul(0x0b, s[4*i+3]), \
                AES.gmul(0x0b, s[4*i]) ^ AES.gmul(0x0d, s[4*i+1]) ^ AES.gmul(0x09, s[4*i+2]) ^ AES.gmul(0x0e, s[4*i+3])

    @staticmethod
    def add_round_key(s, k):
        """
        Combine each byte of the state with a block(16-byte) round key using bitwise xor

        :param list s: 16-byte list of the state
        :param list k: 16-byte list of the subkey
        """
        for i in range(16):
            s[i] ^= k[i]

    # key schedule
    @staticmethod
    def sub_word(w):
        """
        :param list w: 4-byte list
        :return: 4-byte list after substitution
        :rtype: list
        """
        return [AES.Sbox[w[i]] for i in range(4)]

    @staticmethod
    def rot_word(w):
        """
        :param list w: 4-byte list
        :return: 4-byte list after rotation
        :rtype: list
        """
        return w[1:] + w[0:1]

    @staticmethod
    def word_xor(w1, w2):
        """
        Perform XOR operation on two words(4 bytes)

        :param list w1: the first word(4 bytes)
        :param list w2: the second word(4 bytes)
        :return: 4-byte lis after the XOR operation
        :rtype: list
        """
        return [w1[i] ^ w2[i] for i in range(4)]

    @staticmethod
    def key_expansion(k, r):
        """
        Perform a Key Expansion routine to generate a key schedule

        :param list(or bytes) k: the Cipher Key
        :param int r: number of rounds
        :return: generated subkeys
        :rtype: list of 4-byte lists
        """
        # fips-197 Figure 11
        k = list(k)  # in case k is bytes
        Nk = len(k) // 4
        subkeys = [k[i:i + 4] for i in range(0, 4*Nk, 4)]

        i = Nk
        while i < 4*(r+1):
            t = subkeys[i - 1]
            if i % Nk == 0:
                tt = AES.sub_word(AES.rot_word(t))
                t = [tt[0] ^ AES.Rcon[i // Nk]] + tt[1:]
            elif Nk > 6 and i % Nk == 4:
                t = AES.sub_word(t)
            subkeys.append(AES.word_xor(subkeys[i - Nk], t))
            i += 1
        return subkeys

    @staticmethod
    def gmul(a, b):
        """
        Multiplication in GF(2^8).

        :param int a: operand
        :param int b: another operand
        :return: a•b over GF(2^8)
        :rtype: int

        ref: https://en.wikipedia.org/wiki/Finite_field_arithmetic
        """
        # modified peasant's algorithm
        p = 0
        while a and b:
            # each iteration has that `a•b + p` is the product
            if b & 0x1:
                p ^= a
            carry = a & 0x80  # the leftmost bit of a
            a <<= 1
            if carry:
                a ^= 0x11b  # sub 0b1_0001_1011, a.k.a. the irreducible polynomial x^8+x^4+x^3+x^1+1
            b >>= 1
        return p