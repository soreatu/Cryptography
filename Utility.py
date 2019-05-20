# -*- coding: utf-8 -*-

'  Some utility functions for several cipher algorithm implementation  '

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
