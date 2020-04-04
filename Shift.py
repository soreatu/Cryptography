# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2019-05-20)

'''
Shift(or Caesar) Cipher implementation.
'''

# Description: One type of *substitution cipher*
# Idea: shift letters in alphabet

#############################
#  Def.  Shift Cipher       #
#  Let x, y, k ∈ Z₂₆        #
#  Enc: E(x) ≡ x + k mod 26 #
#  Dec: D(y) ≡ y - k mod 26 #
#############################

from string import ascii_uppercase as alphabet

ctoi = lambda c: alphabet.index(c)
itoc = lambda i: alphabet[i]


'''Encryption & Decryption'''
def shift_enc(m, k):
    '''
    Encryption of shift cipher

    :param str m: The message to be encrypted
    :param int k: Key of encrytion, offset of shifting
    :return: cipher after shifting
    :rtype str
    '''
    res = ""
    for ch in m:
        if ch not in alphabet:
            res += ch
        else:
            res += itoc( (ctoi(ch) + k) % len(alphabet))
    return res

def shift_dec(c, k):
    '''
    Decryption of shift cipher

    :param str c: The cipher to be decrypted
    :param int k: Key of decryption, offset of shifting
    :return: message after shifting
    :rtype str
    '''
    res = ""
    for ch in c:
        if ch not in alphabet:
            res += ch
        else:
            res += itoc( (ctoi(ch) - k) % len(alphabet))
    return res

'''Test'''
def test():
    key = 3
    message = "Caesar Cipher".upper()
    print(f"Messgae: {message}")

    cipher = shift_enc(message, key)
    print(f"Cipher: {cipher}")

    decrypted = shift_dec(cipher, key)
    print(f"Decrypted: {decrypted}")

if __name__ == "__main__":
    test()

# Output:
# Messgae: CAESAR CIPHER
# Cipher: FDHVDU FLSKHU
# Decrypted: CAESAR CIPHER