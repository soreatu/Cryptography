# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2019-05-31)

'''
Stream Cipher implementation.
'''

import Utility

def stream_enc(pt, k):
    '''
    Encryption of stream cipher

    :param str or bytes pt: plaintext to be encrypted
    :param list k: key of encryption
    :return: ciphertext after encryption
    :rtype: bytes
    '''
    # type judgement
    if isinstance(pt, bytes):
        bits = Utility.bytes2bits(pt)
    elif isinstance(pt, str):
        bits = Utility.str2bits(pt)
    else:
        raise TypeError("plaintext must be type str or bytes")
    # xor
    c = ""
    for i, v in enumerate(bits):
        c += str(int(v) ^ k[i % len(k)])
    return Utility.bits2bytes(c)

def stream_dec(ct, k):
    '''
    Decryption of stream cipher

    :param bytes ct: ciphertext to be decrypted
    :param list k: key of decryption
    :return: plaintext after decryption
    :rtype: bytes
    '''
    # Decryption of symmetrix cipher shares the same procedures with encryption
    return stream_enc(ct, k)



def lfsr_f(start, taps, l=1<<10):
    '''
    (16-bit) Fibonacci LFSRs(linear-feedback shift registers)

    :param list start: start state that not equals to 0 
    :param list taps: the bits in the LFSR state that influence the input
    :param int l: desired length of output sequence (default: 2**10)
    :return: pseudorandom 0,1 character list
    :rtype: list
    '''
    # only '1' in taps works, get the index of all '1' in taps
    index = []
    for i in range(len(taps)):
        if taps[i]:
            index.append(i)
    pre = start
    key = []
    while l > 0:
        l -= 1
        # calculate output
        output = 0
        for i in index:
            output ^= pre[i]
        key.append(output)
        # left shift and feedback
        pre = [output] + pre[:-1]
    return key


def test():
    start = [1,0,1,0,1,1,0,0,1,1,1,0,0,0,0,1]
    taps = [0,0,0,0,0,0,0,0,0,0,1,0,1,1,0,1]
    key = lfsr_f(start, taps, 11)
    print(key)
    plaintext = "asdfhkjxzcnmcvoiqwueyiuhxcalksdiyqweasd"
    ciphertext = stream_enc(plaintext, key)
    recover = stream_dec(ciphertext, key)
    print(ciphertext)
    print(recover)

if __name__ == "__main__":
    test()