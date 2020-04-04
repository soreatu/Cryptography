# -*- codin: utf-8 -*-
# AUTHOR: Soreat_u (2020-01-28)

'''
NTRUEncrypt (the NTRU public key cryptosystem) implementation.
'''

# Reference: Book "An Introduction to Mathematical Cryptography" Section 7.10.1
class NTRUEncrypt(object):
    '''
    NOTE: This is a BROKEN implementation, for sagemath doesen't implement
    the operations over arbitrary convolution polynomial rings.
    TODO: Implementation that works well.
    '''
    def __init__(N, p, q, d):
        if not is_prime(N) or not is_prime(p) or gcd(p,q) != 1 or gcd(N,q) != 1:
            raise ValueError("Invalid parameters!")

        self.N = N
        self.p = p
        self.q = d
        self.d = d

        Z.<x> = PolynomialRing(ZZ)
        R.<a> = Z.quotient(x^N - 1)
        Zq.<x1> = PolynomialRing(Zmod(q))
        Rq.<b> = Zq.quotient(x1^N - 1)
        Zp.<x2> = PolynomialRing(Zmod(p))
        Rq.<c> = Zp.quotient(x2^N - 1)

    def key_gen():
        while True:
            f = ternary_polynomial_gen(Z, N, d+1, d)
            # Non-integral domain has broken `gcd` and `xgcd` implementation!!!
            if Zq(f).gcd(x^N-1) == 1 and Zp(f).gcd(x^N-1) == 1:
                break
        g = ternary_polynomial_gen(R, N, d, d)
        Fq = Rq(Zq(f).xgcd(a^N-1)[1])
        Fp = Rp(Zp(f).xgcd(b^N-1))
        h = Fq * Rq(g)
        return h, (f,fp)

    def __ternary_polynomial_gen(R, N, d1, d2):
        v = [1]*d1 + [-1]*d2 + [0]*(N-d1-d2)
        shuffle(v)
        return R(v)

    def __center_lift(R, poly, q)
        l = poly.list()
        q2 = q / 2
        for i in range(len(l)):
            l[i] = l[i] % q
            if l[i] > q2:
                l[i] = l[i] - q
        return R(l)

    def encrypt(m, h):
        r = __ternary_polynomial_gen(R, N, d, d)
        e = Rq(self.p*h*r + m)
        return e

    def decrypt(e, f, Fp):
        a = __center_lift(f*e, q)
        b = Fp*a
        return __center_lift(b, p)
