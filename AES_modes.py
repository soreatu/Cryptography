# -*- coding: utf-8 -*-
# Written by *Soreat_u* on June 15th, 2019


'  Modes of AES implementation  '

from AES import AES_enc, AES_dec
import os

def padding(s, Mode="PKCS7"):
    '''
    Padding for AES

    :param bytes s: plaintext need to be padded
    :param str Mode: modes of padding, supporting "ZeorPadding", "PKCS7"(default), "ISO10126", "ANSIX923", "None"
    :return: plaintext after padding
    :rtype: bytes
    '''
    len_pad = 16 - len(s) % 16
    if Mode == "ZeroPadding":
        s += b'\x00' * len_pad
    elif Mode == "PKCS7":
        s += bytes([len_pad]) * len_pad
    elif Mode == "ISO10126":
        s += os.urandom(len_pad-1) + bytes([len_pad])
    elif Mode == "ANSIX923":
        s += b'\x00' * (len_pad-1) + bytes([len_pad])
    elif Mode == "None":
        pass
    else:
        raise ValueError("Wrong mode")
    # check for length
    if len(s) % 16 != 0 and len(s) == 0:
        raise ValueError("The length of plaintext must be the mutiple of 16")
    return s

def AES_ECB_enc(pt, k, pad="PKCS7"):
    '''
    Electronic Codebook Mode encryption of AES

    :param bytes pt: plaintext
    :param bytes k: key
    :param str pad: mode of padding(default PKCS7)
    :return: ciphertext
    :rtype: bytes
    '''
    pt = padding(pt, pad)
    ct = b''
    for i in range(0, len(pt), 16):
        ct += AES_enc(pt[i:i+16], k)
    return ct

def AES_ECB_dec(ct, k):
    '''
    Electronic Codebook Mode decryption of AES

    :param bytes ct: ciphertext
    :param bytes k: key
    :return: plaintext(padded)
    :rtype: bytes
    '''
    pt = b''
    for i in range(0, len(ct), 16):
        pt += AES_dec(ct[i:i+16], k)
    return pt

def AES_CBC_enc(pt, k, IV, pad="PKCS7"):
    '''
    Cipher Block Chaining Mode encryption of AES

    :param bytes pt: plaintext
    :param bytes k: key
    :param bytes IV: initialization vector
    :param str pad: mode of padding(default PKCS7)
    :return: ciphertext
    :rtype: bytes
    '''
    assert isinstance(IV, bytes) and len(IV)==16
    pt = padding(pt, pad)
    ct = b''
    yi = IV
    for i in range(0, len(pt), 16):
        xi = bytes([pt[i+b]^yi[b] for b in range(16)])
        yi = AES_enc(xi, k)
        ct += yi
    return ct

def AES_CBC_dec(ct, k, IV):
    '''
    Cipher Block Chaining Mode decryption of AES

    :param bytes ct: ciphertext
    :param bytes k: key
    :param bytes IV: initialization vector
    :return: plaintext(padded)
    :rtype: bytes
    '''
    assert isinstance(IV, bytes) and len(IV)==16
    pt = b''
    yi_1 = IV
    for i in range(0, len(ct), 16):
        yi = ct[i:i+16]
        xored = AES_dec(yi, k)
        xi = bytes([xored[b] ^ yi_1[b] for b in range(16)])
        pt += xi
        yi_1 = yi
    return pt

def AES_CFB_enc(pt, k, IV, pad="PKCS7"):
    '''
    Cipher Feedback Mode encryption of AES

    :param bytes pt: plaintext
    :param bytes k: key
    :param bytes IV: initialization vector
    :param str pad: mode of padding(default PKCS7)
    :return: ciphertext
    :rtype: bytes
    '''
    assert isinstance(IV, bytes) and len(IV)==16
    pt = padding(pt, pad)
    ct = b''
    yi = IV
    for i in range(0, len(pt), 16):
        si = AES_enc(yi, k)
        xi = pt[i:i+16]
        yi = bytes([xi[b] ^ si[b] for b in range(16)])
        ct += yi
    return ct

def AES_CFB_dec(ct, k, IV):
    '''
    Cipher Feedback Mode decryption of AES

    :param bytes ct: ciphertext
    :param bytes k: key
    :param bytes IV: initialization vector
    :return: plaintext(padded)
    :rtype: bytes
    '''
    assert isinstance(IV, bytes) and len(IV)==16
    pt = b''
    yi_1 = IV
    for i in range(0, len(ct), 16):
        si = AES_enc(yi_1, k)
        yi = ct[i:i+16]
        xi = bytes([yi[b] ^ si[b] for b in range(16)])
        pt += xi
        yi_1 = yi
    return pt

def AES_OFB_enc(pt, k, IV, pad="PKCS7"):
    '''
    Output Feedback Mode encryption of AES
    
    :param bytes pt: plaintext
    :param bytes k: key
    :param bytes IV: initialization vector
    :param str pad: mode of padding(default PKCS7)
    :return: ciphertext
    :rtype: bytes
    '''
    assert isinstance(IV, bytes) and len(IV)==16
    pt = padding(pt, pad)
    ct = b''
    si_1 = IV
    for i in range(0, len(pt), 16):
        si = AES_enc(si_1, k)
        xi = pt[i:i+16]
        yi = bytes([xi[b] ^ si[b] for b in range(16)])
        ct += yi
        si_1 = si
    return ct

def AES_OFB_dec(ct, k, IV):
    '''
    Output Feedback Mode decryption of AES

    :param bytes ct: ciphertext
    :param bytes k: key
    :param bytes IV: initialization vector
    :return: plaintext(padded)
    :rtype: bytes
    '''
    assert isinstance(IV, bytes) and len(IV) == 16
    pt = b''
    si_1 = IV
    for i in range(0, len(ct), 16):
        si = AES_enc(si_1, k)
        yi = ct[i:i+16]
        xi = bytes([yi[b] ^ si[b] for b in range(16)])
        pt += xi
        si_1 = si
    return pt

def AES_CTR_enc(pt, k, IV, pad="PKCS7"):
    '''
    Counter Mode encryption of AES

    :param bytes pt: plaintext
    :param bytes k: key
    :param bytes IV: initialization vector(96-bit in length)
    :param str pad: mode of padding(default PKCS7)
    :return: ciphertext
    :rtype: bytes
    '''
    assert isinstance(IV, bytes) and len(IV)==12
    pt =padding(pt, pad)
    CTR = 0
    ct = b''
    for i in range(0, len(pt), 16):
        si = AES_enc(IV + CTR.to_bytes(4, 'big'), k)
        xi = pt[i:i+16]
        yi = bytes([xi[b] ^ si[b] for b in range(16)])
        ct += yi
        CTR += 1
    return ct

def AES_CTR_dec(ct, k, IV):
    '''
    Counter Mode decryption of AES

    :param bytes ct: ciphertext
    :param bytes k: key
    :param bytes IV: initialization vector(96-bit in length)
    :return: plaintext
    :rtype: bytes
    '''
    assert isinstance(IV, bytes) and len(IV)==12
    CTR = 0
    pt = b''
    for i in range(0, len(ct), 16):
        si = AES_enc(IV + CTR.to_bytes(4, 'big'), k)
        yi = ct[i:i+16]
        xi = bytes([yi[b] ^ si[b] for b in range(16)])
        pt += xi
        CTR += 1
    return pt


def AES_GCM(pt, k, IV, AAD, pad="PKCS7"):
    '''
    Galois Counter Mode of AES

    :param bytes pt: plaintext
    :param bytes k: key
    :param bytes IV: initialization vector(96-bit in length)
    :param bytes AAD: additional authenticated data
    :param str pad: mode of padding(default PKCS7)
    :return: final authentication tag
    :rtype: bytes
    '''
    from Arithemetic import gmul128
    bxor = lambda x, y: bytes([x[i]^y[i] for i in len(x)])
    assert isinstance(IV, bytes) and len(IV)==12
    pt = padding(pt, pad)
    # encrypt CTR0
    CTR = 0
    CTR0 = IV + CTR.to_bytes(4, 'big')
    eCTR0 = AES_enc(CTR0, k)
    # authentication subkey H = Ek(0)
    H = AES_enc(0, k)
    # compute gi
    gi = gmul128(AAD, H)
    for i in range(0, len(pt), 16):
        CTR += 1
        CTRi = IV + CTR.to_bytes(4, 'big')
        si = AES_enc(CTRi, k)
        xi = pt[i:i+16]
        yi = bxor(xi, si)
        gi = gmul128(bxor(gi,yi), H)
    # compute final authentication tag 
    T = bxor(gmul128(gi,H), eCTR0)
    return T
    # not test