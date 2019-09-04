# -*- coding: utf-8 -*-

'Some arithemetic implementation in Python'

# Number-theory-related
def FastModularMultiply(x, y, n):
    '''
    Returns (x * y) % n 
    '''
    x = x % n
    res = 0
    while y != 0:
        if y & 1:
            res = (res + x) % n
        y >>= 1
        x = (2 * x) % n
    return res

def FastModularExponentiation(x, y, n):
    '''
    Square-and-Mutiply for Modular Exponentiation.

    :param int x: base element
    :param int y: exponent
    :param int n: modulus
    :return: x^y % n
    :rtype: int
    '''
    x = x % n
    res = 1
    while y != 0:
        if y & 1:
            res = (res * x) % n
        y >>= 1
        x = (x * x) % n
    return res

def egcd(a, b):
    '''
    Extended Euclidean Algorithm.
    returns x, y, gcd(a,b) such that ax + by = gcd(a,b).
    '''
    u, u1 = 1, 0
    v, v1 = 0, 1
    while b:
        quotient = a // b
        u, u1 = u1, u - quotient * u1
        v, v1 = v1, v - quotient * v1
        a, b = b, a - quotient * b
    return u, v, a

def gcd(a,b):
    '''
    Calculate the Greatest Common Divisor of a, b.
    '''
    # a, b = (b, a) if a < b else (a, b)
    while b:
        a, b = b, a % b
    return a

def ModInverse(e, n):
    '''
    Solve d such that `d * e ≡ 1 (mod n)`.
    N.d. gcd(e, n) must be 1.
    '''
    res, _, g = egcd(e, n)
    assert(g == 1) # e has an inverse modulo n iff gcd(e, n) == 1
    return res % n


def LinearCongruenceEquation(a, c, m):
    '''
    Solve x such that `a * x ≡ c (mod m)`.
    returns all the possible *x*s (mod m), None if no solution.
    '''
    g = gcd(a, m)
    if c % g:
        return None
    u0 = egcd(a, m)[0]
    return [(c * u0 + k * m) // g % m for k in range(g)]


# 中国剩余定理(Chinese Remainder Theorem, CRT)
# 适用于模数两两互质的情况，可以直接通过构造求解。
# def CRT(ai, mi):
#     # # make sure every two *m*s in *mi* are relatively prime
#     # lcm = lambda x, y: x * y // gcd(x, y)
#     # mul = lambda x, y: x * y
#     # assert(reduce(mul, mi) == reduce(lcm, mi))
#     assert(isinstance(mi, list) and isinstance(ai, list))
#     import functools
#     M = functools.reduce(lambda x, y: x * y, mi)
#     ai_ti_Mi = [a * (M // m) * egcd(M // m, m)[0]  for (m, a) in zip(mi, ai)]
#     return functools.reduce(lamdba x, y: x + y, ai_ti_Mi) % M

# 推广，不要求模数两两互质，总体思路是代入合并，再解线性同余方程。
def CRT(ai, mi):
    '''
    Chinese Remainder Theorem.
    solve x such that `x ≡ ai[0] (mod mi[0]) ...`.
    '''
    assert(isinstance(mi, list) and isinstance(ai, list))
    a, m = ai[0], mi[0]
    for a1, m1 in zip(ai[1:], mi[1:]):
        # `x ≡ a (mod m)` ==> `x = a + k * m`
        # substitute in `x ≡ a1 (mod m1)` ==> `k * m ≡ a1 - a (mod m1)`
        k = LinearCongruenceEquation(m, a1 - a, m1) # solve k
        if not k:
            return None
        # The solution is x ≡ a + k * m (mod m * m1)
        a, m = a + k[0] * m, m * m1
    return a



# Finite field (GF(2^8)) arithemetic for AES 
def gadd(a, b):
    '''
    Addition in GF(2^8).

    :param int a
    :param int b
    :return: a+b over GF(2^8)
    :rtype: int
    :ref.: https://en.wikipedia.org/wiki/Finite_field_arithmetic
    '''
    return a ^ b

def gsub(a, b):
    '''
    Subtraction in GF(2^8).

    :param int a
    :param int b
    :return: a-b over GF(2^8)
    :rtype: int
    :ref.: https://en.wikipedia.org/wiki/Finite_field_arithmetic
    '''
    return a ^ b

def gmul(a, b):
    '''
    Multiplication in GF(2^8).

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
        if (carry):
            a ^= 0x11b  # sub 0b1_0001_1011 (Irr. pol. = x8+x4+x3+x1+1)
        b >>= 1
    return p

def gmul128(a, b):
    '''
    Multiplication in GF(2^8).

    :param int a
    :param int b
    :return: return: a•b over GF(2^8)
    :rtype: int
    '''
    p = 0
    while a and b:
        if (b & 0x1):
            p ^= a
        carry = a & (1 << 127)
        a <<= 1
        if (carry):
            a ^= (1 << 128) + 0x86  # Irr. pol. = x128+x7+x2+x1
        b >>= 1
    return p
    # not test



# square-related
def isqrt(n):
    '''
    Calculates the integer square root
    for arbitrary large nonnegative integers
    '''
    if n < 0:
        raise ValueError('square root not defined for negative numbers')
    
    if n == 0:
        return 0
    a, b = divmod(n.bit_length(), 2)
    x = 2**(a+b)
    while True:
        y = (x + n//x)//2
        if y >= x:
            return x
        x = y

def is_perfect_square(n):
    '''
    If n is a perfect square it returns sqrt(n),
    
    otherwise returns -1
    '''
    h = n & 0xF; #last hexadecimal "digit"
    
    if h > 9:
        return -1 # return immediately in 6 cases out of 16.

    # Take advantage of Boolean short-circuit evaluation
    if ( h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8 ):
        # take square root if you must
        t = isqrt(n)
        if t*t == n:
            return t
        else:
            return -1
    
    return -1