# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2019-09-14)

'''
Some arithemetic implementation.
'''

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
        q, r = divmod(a, b)
        u, u1 = u1, u - q * u1
        v, v1 = v1, v - q * v1
        a, b = b, r
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

def LinearCongruenceSolver(a, c, m):
    '''
    Solve x such that `a * x ≡ c (mod m)`,
    returns all the possible *x*s (mod m), None if no solution.
    '''
    g = gcd(a, m)
    if c % g:
        return None
    u0 = egcd(a, m)[0]
    return [(c * u0 + k * m) // g % m for k in range(g)]

def ModSquareRoot(a, p):
    '''
    Solve x such that `x^2 ≡ a (mod p)` where p is a prime,
    returns all the solution(s), None if no solution.
    '''
    # assert(isPrime(p))
    l = Legendre(a, p)  # The Legendre symbol of a over p.
    if l == -1:
        return None
    elif l == 0:
        return [0]

    if p % 4 == 3:  # which is quite easy to compute.
        R = pow(a, (p + 1) // 4, p)
        return [R, p - R]
    else:
        return TonelliShanksAlgorithm(a, p)

def TonelliShanksAlgorithm(a, p):
    '''
    Solve the equation `x^2 ≡ a (mod p)` where `p ≡ 1 (mod 4)`.
    returns all the two solutions to the equation.
    '''
    # 1. Factor `p - 1` into `2^S * Q` where Q is odd.
    Q = p - 1
    S = 0
    while Q & 1 == 0:
        S += 1
        Q //= 2
    # 2. Find a NR(p).
    y = 2
    while Legendre(y, p) != -1:
        y += 1
    # 3. Calculate the four quantities.
    R = pow(a, (Q + 1) // 2, p)
    c = pow(y, Q, p)
    t = pow(a, Q, p)
    E = S
    # 4. Loop.
    while t != 1:
        for i in range(1, E):
            if pow(t, 2 ** i, p) == 1:
                break
        b = pow(c, 2 ** (E - i - 1), p)
        R = R * b % p
        c = pow(b, 2, p)
        t = c * t % p
        E = i
    return [R, p - R]

def Legendre(a, p):
    '''
    The Legendre Sybmol.
    returns 1 if a is QR(p), or -1 if NR(p), or 0 if a divides p.
    '''
    if a % p == 0:
        return 0
    # Euler's Criterion
    return 1 if pow(a, (p - 1) // 2, p) == 1 else -1


# Constructive solution for coprime moduli.
def CRT_constructive(ai, mi):
    # # make sure every two *m*s in *mi* are relatively prime
    # lcm = lambda x, y: x * y // gcd(x, y)
    # mul = lambda x, y: x * y
    # assert(reduce(mul, mi) == reduce(lcm, mi))
    assert(isinstance(mi, list) and isinstance(ai, list))
    from functools import reduce
    M = reduce(lambda x, y: x * y, mi)
    ai_ti_Mi = [a * (M // m) * egcd(M // m, m)[0]  for (m, a) in zip(mi, ai)]
    return reduce(lambda x, y: x + y, ai_ti_Mi) % M

# Recursive solution.
def CRT_recursive(ai, mi):
    '''
    Chinese Remainder Theorem.
    Solve one x such that `x ≡ ai[0] (mod mi[0]) ...`.
    '''
    assert(isinstance(mi, list) and isinstance(ai, list))
    a, m = ai[0], mi[0]
    for a1, m1 in zip(ai[1:], mi[1:]):
        # `x ≡ a (mod m)` ==> `x = a + k * m`
        # substitute in `x ≡ a1 (mod m1)` ==> `k * m ≡ a1 - a (mod m1)`
        k = LinearCongruenceSolver(m, a1 - a, m1) # solve k
        if not k:
            return None
        # The solution is x ≡ a + k * m (mod m * m1)
        a, m = a + k[0] * m, m * m1
    return a

def CRT_recursive_all(ai, mi):
    '''
    Chinese Remainder Theorem.
    Solve all x such that `x ≡ ai[0] (mod mi[0]) ...`.
    '''
    assert(isinstance(mi, list) and isinstance(ai, list))
    a_s, m = set([ai[0]]), mi[0]
    for a1, m1 in zip(ai[1:], mi[1:]):
        # print(f"m1: {m1}")
        new_as = set()
        for a in a_s:
            ks = LinearCongruenceSolver(m, a1 - a, m1)
            if not ks:
                continue
            for k in ks:
                new_as.add(a + k*m)
        a_s = new_as
        m = m * m1
    return a_s, m

# Default CRT.
CRT = CRT_constructive

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
            a ^= 0x11b  # sub 0b1_0001_1011 a.k.a. Irreducible poly. = x8+x4+x3+x1+1
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
# def isqrt(n):
#     """
#     Returns x such that x = floor(sqrt(n))

#     Ref: https://en.wikipedia.org/wiki/Integer_square_root
#     """
#     xk = n
#     xkp1 = (xk + n//xk) // 2
#     while abs(xkp1 - xk) >= 1:
#         xk = xkp1
#         xkp1 = (xk + n//xk) // 2
#     return xkp1


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
    Returns sqrt(n) if n is a perfect square, -1 otherwise.
    '''
    h = n & 0xF; # last hexadecimal "digit"

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