# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2019-05-20)

'''
Some utility functions for several cipher algorithms implementation.
'''

def BlockXor(bx, by):
    '''
    Xor each of the element in the two blocks
    '''
    result = []
    for i in range(len(bx)):
        result.append(bx[i] ^ by[i])
    return result # ok

def String2Block(s):
    '''
    Convert string to bit block
    '''
    result = []
    for i in s:
        for j in range(8):
            result.append(ord(i) >> (7-j) & 1) # Little-Endian ???
    return result  # ok

def Bytes2Block(b):
    '''
    Convert bytes to bit block
    '''
    result = []
    for i in b:
        for j in range(8):
            result.append(i >> (7 - j) & 1)
    return result # ok

def Block2String(b):
    '''
    Convert bit block to string
    '''
    result = ""
    for i in range(8):
        dec = 0 # get the decimal of 8 bits
        for j in range(8):
            dec += b[i * 8 + j] << (7 - j)
        result += chr(dec)
    return result  # ok

def Block2Bytes(b):
    '''
    Convert bit block to bytes
    '''
    result = b""
    for i in range(8):
        dec = 0
        for j in range(8):
            dec += b[i * 8 + j] << (7 - j)
        result += bytes([dec])
    return result # ok

def Permute(block, p):
    '''
    Do the general permutation
    '''
    result = []
    try:
        for i in range(len(p)):
            result.append(block[p[i]-1])
    except IndexError:
        print("Permutation is out of index of the block")
    return result # ok

def bytes2bits(b):
    '''
    convert bytes to binary representation

    :param bytes b
    :rtype: str
    '''
    return ''.join(bin(i)[2:].rjust(8, '0') for i in b) # ok

def str2bits(s):
    '''
    convert string to binary representation

    :param str s
    :rtype: str
    '''
    return ''.join(bin(ord(i))[2:].rjust(8, '0') for i in s) # ok

def bits2bytes(b):
    '''
    convert bits to bytes representation

    :param str b: 0,1 character sequences
    :rtype: bytes
    '''
    return b''.join(bytes([int(b[i: i + 8], 2)]) for i in range(0, len(b), 8)) # ok

def bits2str(b):
    '''
    convert bits to str representation

    :param str b: 0,1 character sequences
    :rtype: str
    '''
    return ''.join(chr(int(b[i:i+8],2)) for i in range(0,len(b),8)) # ok
