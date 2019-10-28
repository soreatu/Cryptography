# -*- coding: utf-8 -*-

'Vigenere Cipher scheme implementation and some powerful attack methods implementation'

from itertools import cycle
from string import ascii_lowercase as alphabet

LETTER_FREQUENCY = {  # From https://en.wikipedia.org/wiki/Letter_frequency.
    'e': 0.12702,
    't': 0.09056,
    'a': 0.08167,
    'o': 0.07507,
    'i': 0.06966,
    'n': 0.06749,
    's': 0.06327,
    'h': 0.06094,
    'r': 0.05987,
    'd': 0.04253,
    'l': 0.04025,
    'c': 0.02782,
    'u': 0.02758,
    'm': 0.02406,
    'w': 0.02360,
    'f': 0.02228,
    'g': 0.02015,
    'y': 0.01974,
    'p': 0.01929,
    'b': 0.01492,
    'v': 0.00978,
    'k': 0.00772,
    'j': 0.00153,
    'x': 0.00150,
    'q': 0.00095,
    'z': 0.00074
}

'''Encryption & Decryption'''
def Vigenere_enc(pt, k):
    '''
    Encryption of Vigenere Cipher.

    :param str pt: The plaintext to be encrypted.
    :param str k: The keyword to encrypt the plaintext.
    :return: The ciphertext after encryption.
    :rtype: str
    '''
    shifts = cycle(alphabet.index(c) for c in k)
    ct = ''
    for c in pt.lower():
        if c not in alphabet: continue
        ct += alphabet[(alphabet.index(c) + next(shifts)) % len(alphabet)]
    return ct

def Vigenere_dec(ct, k):
    '''
    Decryption of Vigenere Cipher.

    :param str ct: The ciphertext to be decrypted.
    :param str k: The keyword to decrypt the ciphertext.
    :return: The plaintext after decryption.
    :rtype: str
    '''
    shifts = cycle(alphabet.index(c) for c in k)
    pt = ''
    for c in ct.lower():
        if c not in alphabet: continue
        pt += alphabet[(alphabet.index(c) - next(shifts)) % len(alphabet)]
    return pt


'''Some powerful attack methods'''
def IndCo(s):
    '''
    Index of Coincidence.

    :param str s: The Substring.
    :return: The index of coincidence of the substring.
    :rtype: float
    '''
    N = len(s)
    frequency = [s.count(c) for c in alphabet]
    return sum(i**2 - i for i in frequency) / (N**2 - N)

def CalKeyLength(s):
    '''
    Calculate the probable key lengths using the index of coincidence method.

    :param str s: The character string to be analysed.
    :return: All the probable key lengths.
    :rtype: list
    '''
    res = []
    for kl in range(2, 100):  # Key length range can be adjusted accordingly.
        subs = [s[i::kl] for i in range(kl)]  # Group into substrings.
        if sum(IndCo(si) for si in subs) / kl > 0.06:
            if all(map(lambda x: kl % x, res)):  # Avoid multiples.
            	res.append(kl)
    return res

def RecoverKeyword_1(ct, kl):
    '''
    Recover the keyword according to the most frequent letters.

    :param str ct: The ciphertext.
    :param int kl: The key length.
    :return: The recovered keyword.
    :rtype: str
    '''
    keyword = ''
    subs = [ct[i::kl] for i in range(kl)]
    for s in subs:
        frequency = [s.count(c) for c in alphabet]
        most_fqc = max(frequency)
        keyword += alphabet[(frequency.index(most_fqc) - 4) % len(alphabet)]
    return keyword

def ChiSquared(s):
    '''
    Calculate the `Chi-squared Statistic`.

    :param str s: The string to be analysed.
    :return: The `Chi-squared Statistic` of the string.
    :rtype: float
    '''
    f = lambda c: LETTER_FREQUENCY[c] * len(s)
    return sum((s.count(c) - f(c))**2 / f(c) for c in alphabet)

def RecoverKeyword_2(ct, kl):
    '''
    Recover the keyword according to the `Chi-squared Statistic`.

    :param str ct: The ciphertext.
    :param int kl: The key length.
    :return: The recovered keyword.
    :rtype: str
    '''
    keyword = ''
    subs = [ct[i::kl] for i in range(kl)]
    for s in subs:
        chi_squareds = []
        for shift in range(len(alphabet)):  # Try all possible shifts.
            shifted_s = ''.join(\
                alphabet[(alphabet.index(c) - shift) % len(alphabet)]\
                for c in s)
            cs = ChiSquared(shifted_s)
            chi_squareds.append((shift, ChiSquared(shifted_s)))
        keyword += alphabet[min(chi_squareds, key=lambda x: x[1])[0]]
    return keyword