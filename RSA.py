# -*- coding: utf-8 -*-
# Written by *Soreat_u* on ...


'  RSA implementation in Python  '

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
def RSA_keygen(n):
    '''
    RSA key generation

    :param int n: bit length of prime p,q
    :return: public key {'e':xx, 'n':xx} and private key {'d':xx, 'n':xx, 'p':xx, 'q':xx}
    :rtype: tuple of dicts
    '''
    pub_key = {}
    pri_key = {}
    p = getprime(n)
    q = getprime(n)
    n = p * q
    phi = (p-1) * (q-1)
    while 1:
        e = random.randint(1, phi-1)
        if Arithemetic.gcd(e, phi) == 1:
            pub_key['e'] = e
            pub_key['n'] = n
            pri_key['p'] = p
            pri_key['q'] = q
            pri_key['d'] = Arithemetic.modInverse(e, n)
            pri_key['n'] = n
            return (pub_key, pri_key)

# Fast Decryption with the Chinese Remainder Theorem
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
    cp = Arithemetic.modInverse(q, p)
    cq = Arithemetic.modInverse(p, q)
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
        s -=1
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
def getprime(n):
    '''
    Prime generator

    :param int n: bit length of prime
    :return: a n-bit prime
    :rtype: int
    '''
    while 1:
        # get one n-bit odd number
        p = random.getrandbits(n)
        while p & 1 == 0:
            p = random.getrandbits(n)
        # prime test
        if MillerRabin_Primality_Test(p, 20):
            return p

# padding
# todo