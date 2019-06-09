# -*- coding: utf-8 -*-

'  Some arithemetic implementation in Python'

def egcd(a,b):
    '''
    Extended Euclidean Algorithm
    returns x, y, gcd(a,b) such that ax + by = gcd(a,b)
    '''
    u, u1 = 1, 0
    v, v1 = 0, 1
    while b:
        q = a // b
        u, u1 = u1, u - q * u1
        v, v1 = v1, v - q * v1
        a, b = b, a - q * b
    return u, v, a

def gcd(a,b):
    '''
    2.8 times faster than egcd(a,b)[2]
    '''
    a,b=(b,a) if a<b else (a,b)
    while b:
        a,b=b,a%b
    return a

def modInverse(e,n):
    '''
    d such that de ≡ 1 (mod n)
    e must be coprime to n
    this is assumed to be true
    '''
    return egcd(e, n)[0] % n


# Finite field arithemetic for AES ( GF(2^8) )
def gadd(a, b):
    '''
    Addition in GF(2^8)

    :param int a
    :param int b
    :return: a+b over GF(2^8)
    :rtype: int
    :ref.: https://en.wikipedia.org/wiki/Finite_field_arithmetic
    '''
    return a ^ b

def gsub(a, b):
    '''
    Subtraction in GF(2^8)

    :param int a
    :param int b
    :return: a-b over GF(2^8)
    :rtype: int
    :ref.: https://en.wikipedia.org/wiki/Finite_field_arithmetic
    '''
    return a ^ b

def gmul(a, b):
    '''
    Multiplication in GF(2^8)

    :param int a
    :param int b
    :return: a•b over GF(2^8)
    :rtype: int
    :ref.: https://en.wikipedia.org/wiki/Finite_field_arithmetic
    '''
    # modified peasant's algorithm
    p = 0
    while a and b:
        # each iteration has that `a•b + p` is the product
        if (b & 0x1):
            p ^= a
        carry = a & 0x80 # the leftmost bit of a
        a <<= 1 
        if (carry): a ^= 0x11b  # sub 0b1_0001_1011 (Irr. pol. = x8+x4+x3+x1+1)
        b >>= 1
    return p