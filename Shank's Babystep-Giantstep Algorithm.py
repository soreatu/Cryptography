# -*- coding: utf-8 -*-
# Written by *Soreat_u* on September 4th, 2019

'''
Shank's Babystep-Giantstep Algorithm to solve the DLP over GF(p) in O(sqrt(N)) steps.
'''

from Arithmetic import isqrt, ModInverse,\
                        FastModularMultiply as mulmod,\
                        FastModularExponentiation as powmod


def DiscreteLog(g, h, p):
    '''
    Solve x such that g^x = h over GF(p).
    '''
    sqrt_n = isqrt(p) + 1

    # Compute the baby steps and store them in the 'precomputed' hash table.
    precomputed = {}
    r = 1
    for i in range(sqrt_n + 1):
        precomputed[r] = i
        r = r * g % p

    # Now compute the giant steps and check the hash table for any matching.
    r = h
    s = pow(ModInverse(g, p), sqrt_n, p)
    for j in range(sqrt_n + 1):
        try:
            i = precomputed[r]
        except KeyError:
            pass
        else:
            # steps = sqrt_n + j
            logarithm = i + sqrt_n * j
            return logarithm
        r = r * s % p

def test():
    # 50-bit p: 3.3GB RAM
    g, h, p = 6, 448509460363890, 1057584323171191
    x = DiscreteLog(g, h, p)
    print(f"{g}^{x} % {p} == {h}")

if __name__ == '__main__':
    test()