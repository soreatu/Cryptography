# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2019-07-04)

import math

'''
The RSA Public Key Cryptosystem implementation.
'''

import random
import Arithmetic

# encryption & decryption function
def RSA_enc(pt, pub_key):
    '''
    Encryption of RSA

    :param int pt: integer representation of plaintext
    :param dict pub_key: public key {'e':xx, 'n':xx}
    :return: ciphertext after encryption
    :rtype: int
    '''
    return pow(pt, pub_key['e'], pub_key['n'])

def RSA_dec(ct, pri_key):
    '''
    Decryption of RSA

    :param int ct: integer representation of ciphertext
    :param dict pri_key: private key {'d':xx, 'n':xx, 'p':xx, 'q':xx}
    :return: plaintext after decryption
    :rtype: int
    '''
    return pow(ct, pri_key['d'], pri_key['n'])

# key generation
def RSA_keygen(bits):
    '''
    RSA key generation

    :param int bits: bit length of the modulus n.
    :return: public key {'e':xx, 'n':xx} and private key {'d':xx, 'n':xx, 'p':xx, 'q':xx}
    :rtype: tuple of dicts
    '''
    pub_key = {}
    pri_key = {}
    p = getprime(bits//2)
    q = getprime(bits//2)
    n = p * q
    phi = (p-1) * (q-1)
    while True:
        e = random.randint(1, phi-1)
        if Arithmetic.gcd(e, phi) == 1:
            pub_key['e'] = e
            pub_key['n'] = n
            pri_key['p'] = p
            pri_key['q'] = q
            pri_key['d'] = Arithmetic.ModInverse(e, phi)
            pri_key['n'] = n
            return (pub_key, pri_key)

# Fast Decryption with the Chinese Remainder Theorem Optimization
def RSA_fast_dec(ct, pri_key):
    '''
    RSA fast decryption(by a factor of 4)

    :param int ct: integer representation of ciphertext
    :param dict pri_key: private key {'d':xx, 'n':xx, 'p':xx, 'q':xx}
    :return: plaintext after decryption
    :rtype: int
    '''
    n, d, p, q = pri_key['n'], pri_key['d'],pri_key['p'],pri_key['q']
    xp = ct % p
    xq = ct % q
    dp = d % (p-1)
    dq = d % (q-1)
    yp = pow(xp, dp, p)
    yq = pow(xq, dq, q)
    cp = Arithmetic.ModInverse(q, p)
    cq = Arithmetic.ModInverse(p, q)
    return (q*cp*yp+p*cq*yq) % n

# Primality Tests
def Fermat_Primality_Test(p, s):
    '''
    Fermat Primality Test based on Fermat's theorem

    :param int p: candidate prime
    :param int s: security parameter
    :return: False if p is composite, True if p is likely prime
    :rtype: bool
    '''
    while s:
        a = random.randint(2, p-2)
        if pow(a, p-1, p) != 1:
            return False
        s -= 1
    return True

def MillerRabin_Primality_Test(p, s):
    '''
    MillerRabin Primality Test

    :param int p: candidate prime
    :param int s: security parameter
    :return: False if p is composite, True if p is likely prime
    :rtype: bool
    '''
    # find `r`,`u` such that p-1 = 2^u*r where r is odd
    u = 0
    r = p-1
    while r & 1 == 0:
        u += 1
        r //= 2
    # test
    while s:
        a = random.randint(2, p-2)
        z = pow(a, r, p)
        if z != 1 and z != p-1:
            for j in range(1, u):
                z = pow(z, 2, p)
                if z == 1:
                    return False
            if z != p-1:
                return False
        s -= 1
    return True

# Prime generator
def getprime(bits):
    '''
    Prime generator

    :param int bits: bit length of prime
    :return: a n-bit prime
    :rtype: int
    '''
    while True:
        # get one odd number
        p = random.getrandbits(bits)
        while p & 1 == 0:
            p = random.getrandbits(bits)
        # prime test
        rabin_miller_rounds = int(math.ceil(-math.log(1e-6)/math.log(4)))
        if MillerRabin_Primality_Test(p, rabin_miller_rounds):
            return p

def test():
    print("Generating RSA parameters...")
    pub, pri = RSA_keygen(1024)

    m = int.from_bytes(b"Test plaintext", 'big')
    c = RSA_enc(m, pub)
    decrypted_1 = RSA_dec(c, pri)
    decrypted_2 = RSA_fast_dec(c, pri)
    assert decrypted_1 == decrypted_2

    print(f"Message: {m}")
    print(f"Cipher: {c}")
    print(f"Decrypted: {decrypted_1}")

if __name__ == "__main__":
    test()