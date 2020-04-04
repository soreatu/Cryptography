# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2019-05-20)

'''
Affine Cipher implementation.
'''

# Description: One type of monoalphabetic *substitution cipher*

# +---------------------------------------+
# |  Def.  Affine Cipher                  |
# |  Let a·a⁻¹ ≡ 1 mod 26                 |
# |  k = (a, b)                           |
# |  Enc: eₖ(x) = y ≡ a·x + b mod 26      |
# |  Dec: dₖ(y) = x ≡ a⁻¹·(y - b) mod 26  |
# +--------------------------------------+

from string import ascii_uppercase as alphabet
from Arithmetic import ModInverse

ctoi = lambda c: alphabet.index(c)
itoc = lambda i: alphabet[i]

'''Encryption & Decryption'''
def affine_enc(message, key):
    '''
    Encryption of affine cipher

    :param str message: The message to be encrypted
    :param dict key: The key for encryption
    :return: cipher after encryption
    :rtype str
    '''
    res = ""
    a, b = key['a'], key['b']
    for m in message:
        if m not in alphabet:
            res += m
        else:
            res += itoc((a * ctoi(m) + b) % len(alphabet))
    return res

def affine_dec(cipher, key):
    '''
    Decryption of affine cipher

    :param str cipher: The cipher to be decrypted
    :param dict key: The key for decrytion
    :return: message after decryption
    :rtype str
    '''
    res = ""
    inv_a, b = ModInverse(key['a'], len(alphabet)), key['b']
    for c in cipher:
        if c not in alphabet:
            res += c
        else:
            res += itoc(inv_a * (ctoi(c) - b) % len(alphabet))
    return res


def test():
    key = {
        "a": 5,
        "b": 8
    }
    message = "AFFINE CIPHER"
    print(f"Message: {message}")

    cipher = affine_enc(message, key)
    print(f"Cipher: {cipher}")

    decrypted = affine_dec(cipher, key)
    print(f"Decrypted: {decrypted}")

if __name__ == "__main__":
    test()

# output:
# Message: AFFINE CIPHER
# Cipher: IHHWVC SWFRCP
# Decrypted: AFFINE CIPHER


'''Attack'''
# - Brute force
# - Frequency analysis