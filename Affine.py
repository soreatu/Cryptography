# -*- coding: utf-8 -*-

'  Affine Cipher  '
# Description: One type of monoalphabetic *substitution cipher*

# +---------------------------------------+
# |  Def.  Affine Cipher                  |
# |  Let a·a⁻¹ ≡ 1 mod 26                 |
# |  k = (a, b)                           |
# |  Enc: eₖ(x) = y ≡ a·x + b mod 26      |
# |  Dec: dₖ(y) = x ≡ a⁻¹·(y - b) mod 26  |
# +--------------------------------------+

from Arithmetic import modInverse

'''Encryption & Decryption'''
def affine_enc(m, k):
    '''
    Encryption of affine cipher

    :param str m: The message to be encrypted
    :param list k: The key for encryption
    :return: cipher after encryption
    :rtype str
    '''
    m = m.upper().replace(' ', '')
    result = ""
    for i in m:
        result += chr((k[0] * (ord(i) - ord('A')) + k[1]) % 26 + ord('A'))
    return result

def affine_dec(c, k):
    '''
    Decryption of affine cipher

    :param str c: The cipher to be decrypted
    :param list k: The key for decrytion
    :return: message after decryption
    :rtype str
    '''
    c = c.upper().replace(' ', '')
    result = ""
    inv = modInverse(k[0], 26)
    for i in c:
        result += chr(inv * (ord(i) - ord('A') - k[1]) % 26 + ord('A'))
    return result


'''Attack'''
# - Frequency analysis
# - Brute-force

# to-do