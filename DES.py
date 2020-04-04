# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2019-05-14)

'''
DES (Data Encryption Standard) implementation.
'''

from Utility import Block2Bytes, BlockXor, Bytes2Block, Permute

'''Permutation Table'''
IP_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
] # ok

FP_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
] # ok

Expansion_table = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
] # ok

Permutation_table = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
] # ok

# There used to be a left PC-1 table and a right one,
# here I merge them into one table
PC_1_table = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
] # ok

PC_2_table = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
] # ok

sbox = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    ]
] # ok


'''Process Function'''
# IP and FP are inverses(IP "undoes" the action of FP, and vice versa)
def IP(block):
    '''
    Initial permutation
    '''
    return Permute(block, IP_table) # ok

def FP(block):
    '''
    Final permutation
    '''
    return Permute(block, FP_table) # ok


# Feistel function
def Feistel(HalfBlock, subkey):
    '''
    The F-function, operating on half a block (32 bits) at a time and consisting of four stages:
    1. Expansion, 2. Key mixing, 3. Substitution, 4. Permutation
    '''
    eHalfBlock = Expansion(HalfBlock)
    xHalfBlock = BlockXor(eHalfBlock, subkey)
    sHalfBlock = Substitution(xHalfBlock)
    return Permutation(sHalfBlock) # ok

def Expansion(HalfBlock):
    '''
    Expand 32-bit half-block to 48 bits using the expansion permutation.
    32-bit -> 48-bit
    '''
    return Permute(HalfBlock, Expansion_table) # ok

def Substitution(HalfBlock):
    '''
    Divide the block into eight 6-bit pieces and then use S-boxes(substitution boxes) to process the eight pieces.
    After processing, the block is reduced from 48 bits to 32 bits.
    48-bit -> 32-bit
    '''
    result = []
    for i in range(8):
        result += S_box(HalfBlock[6*i:6*i+6], i)
    return result

def S_box(piece, i):
    '''
    Replace the six input bits with four output bits according to a non-linear transformation, provided in the form of a loopup table.
    S-boxes provide the core of the security of DES, without which the cipher would be linear and easily broken.
    6-bit -> 4-bit
    '''
    row = (piece[0] << 1) + piece[-1]
    col = (piece[1] << 3) + (piece[2] << 2) + (piece[3] << 1) + piece[4]
    s = sbox[i][16 * row + col]
    result = []
    for j in range(4):
        result.append((s >> (3 - j)) & 1)
    return result # ok

def Permutation(HalfBlock):
    '''
    Rearrange the 32 outputs from the S-boxes according to a fixed permutation
    '''
    return Permute(HalfBlock, Permutation_table) # ok


'''Encryption & Decryption'''
# Decryption uses the same structure as encryption, but merely with the keys used in reverse order.
def DES_enc(m, subkey):
    '''
    Encryption of DES.

    :param bytes m: The message to be encrypted.
    :param list key: The subkey to encrypt the message.
    :return: The cipher after encryprtion.
    :rtype: bytes
    :raises TypeError: if the type of m is not `bytes`.
    :raises ValueError: if message is not 8-byte in length.
    '''
    if type(m) != bytes:
        raise TypeError("message must be type `bytes`")
    elif len(m) != 8:
        raise ValueError("message must be 64-bit in length")
    # convert `bytes` m to block
    m = Bytes2Block(m)
    # Initial permutation
    m = IP(m)
    # divide the block into two 32-bit halves
    Li, Ri = m[:32], m[32:]
    # 16 rounds
    for i in range(16):
        Li, Ri = Ri, BlockXor(Li, Feistel(Ri, subkey[i]))
    # merge the two divided half block which is 32-bit into one 64-bit block
    m = Ri + Li # There is a need to change order of the final two halves
    # Final permutation
    m = FP(m)
    # convert `block` m to `bytes`
    return Block2Bytes(m) # ok

def DES_dec(c, subkey):
    '''
    Decryption of DES.

    :param bytes c: The cipher to be decrypted
    :param list subkey: The subkey to decrypt the cipher
    :return: the message after decryption
    :rtype: bytes
    :raises TypeError: if the type of c is not `bytes`
    :raises ValueError: if cipher is not 8-byte in length
    '''
    # Since decryption shares a lot similarity with encryption and the very difference between them\
    # is the subkey (reversed), decryption is actually another form of encryption.
    return DES_enc(c, subkey[::-1]) # ok


'''Key schedule'''
def gen_key(key):
    '''
    Generate the sixteen subkeys according to the key.

    :param bytes key: The key to generate sixteen subkeys
    :return: lists of the sixteen subkeys
    :rtype: list
    :raises TypeError: if the type of key is not `bytes`
    :raises ValueError: if @key is not 56-bit or 64-bit in length
    '''
    # convert string key to bytes key
    if type(key) != bytes:
        raise TypeError("key must be type `bytes`")
    bkey = Bytes2Block(key)
    subkey = []
    if len(bkey) == 64:
        # PC-1
        bkey = PC_1(bkey)
    elif len(bkey) != 56:
        raise ValueError("key must be 56-bit or 64-bit in length")
    # divide the block into two halves
    Ci, Di = bkey[:28], bkey[28:]
    for i in range(16):
        # Left Rotation
        Ci, Di = LR(Ci, Di, i)
        # PC-2
        subkey.append(PC_2(Ci + Di))
    return subkey # ok

def PC_1(key):
    '''
    Permutation Choice 1
    Discard the parity check bits, which cuts the 64-bit key into 56-bit key and then permute.
    64-bit -> 56-bit
    '''
    return(Permute(key, PC_1_table)) # ok

def LR(Ci, Di, i):
    '''
    Left Rotate the halfblock according to i.
    '''
    # 1 position shift if i = 1, 2, 9, 16 while 2 position shift all other i
    keyoff = [1, 2, 9, 16]
    if i + 1 in keyoff:
        Ci, Di = Ci[1:] + Ci[0:1], Di[1:] + Di[0:1]
    else:
        Ci, Di = Ci[2:] + Ci[0:2], Di[2:] + Di[0:2]
    return Ci, Di # ok

def PC_2(CiDi):
    '''
    Permutation Choice 2.
    Drop 8 bits and permute the remaining 48 input bits.
    56-bit -> 48-bit
    '''
    return(Permute(CiDi, PC_2_table)) # ok



'''Test'''
def test():
    m = b"desisbad"
    key = b"Imnotkey"
    subkey = gen_key(key)
    cipher = DES_enc(m, subkey)
    message = DES_dec(cipher, subkey)
    print(b"Message: " + message)
    print(b"Key: " + key)
    print(b"Cipher: " + cipher)

if __name__ == "__main__":
    test()

# output:
# b'Message: desisbad'
# b'Key: Imnotkey'
# b'Cipher: \x0e2#b\xf9\xd4\xe5\x05'