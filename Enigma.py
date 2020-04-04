# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2020-04-04)

"""
The Enigma Machine Implementation.
"""

from collections import namedtuple
from string import ascii_uppercase as alphabet


class Enigma:

    def __init__(self, inital_state):
        self.times = 0
        self.slow_wheel = inital_state.slow_wheel
        self.medium_wheel = inital_state.medium_wheel
        self.fast_wheel = inital_state.fast_wheel

    @staticmethod
    def _ctoi(ch):
        return alphabet.index(ch)

    @staticmethod
    def _itoc(i):
        return alphabet[i]

    @staticmethod
    def _rotate_single_wheel(table, one):
        res = ""
        for ch in alphabet:
            tmp = table[(Enigma._ctoi(ch) - one) % 26]
            res += Enigma._itoc( (Enigma._ctoi(tmp) + one) % 26 )
        return res

    def _rotate_wheels(self, one):
        self.fast_wheel = Enigma._rotate_single_wheel(self.fast_wheel, one)
        if self.times % 26 == 0:
            self.medium_wheel = Enigma._rotate_single_wheel(self.medium_wheel, one)
        if self.times % 26**2 == 0:
            self.slow_wheel = Enigma._rotate_single_wheel(self.fast_wheel, one)

    def _rotation(self, encrypt: bool):
        if encrypt == True:
            self.times += 1
            self._rotate_wheels(1)
        else:
            self._rotate_wheels(-1)
            self.times -= 1

    def encrypt(self, plaintext):
        return "".join(self._encrypt_single(m) for m in plaintext)

    def decrypt(self, ciphertext):
        return "".join(self._decrypt_single(c) for c in ciphertext[::-1])[::-1]

    def _encrypt_single(self, m):
        if m not in alphabet: return m
        tmp = self.slow_wheel[Enigma._ctoi(m)]
        tmp = self.medium_wheel[Enigma._ctoi(tmp)]
        res = self.fast_wheel[Enigma._ctoi(tmp)]
        self._rotation(encrypt=True)
        return res

    def _decrypt_single(self, c):
        if c not in alphabet: return c
        self._rotation(encrypt=False)
        tmp = Enigma._itoc(self.fast_wheel.index(c))
        tmp = Enigma._itoc(self.medium_wheel.index(tmp))
        res = Enigma._itoc(self.slow_wheel.index(tmp))
        return res



def test():
    State = namedtuple("State",["slow_wheel", "medium_wheel", "fast_wheel"])
    initial_state = State(
        # Substitution Table, i.e., after slow wheel, A->Y B->W ... Z->T.
                     # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        slow_wheel =   "YWHDVBNPXLJRFOSZGCKQUEIAMT",
        medium_wheel = "YBLFDJCTVXUOHSGEKZPNAWMIRQ",
        fast_wheel =   "YWHKMTXAOGJPIZURDBSEVFLNQC",
    )
    enigma = Enigma(initial_state)

    # message = "AAAAAAAAAAAAAAAAAAAA"
    message = "The quick brown fox jumps over the lazy dog".upper()
    print(f"Message: {message}")
    cipher = enigma.encrypt(message)
    print(f"Cipher: {cipher}")
    decrypted = enigma.decrypt(cipher)
    print(f"Decrypted message: {decrypted}")

if __name__ == "__main__":
    test()