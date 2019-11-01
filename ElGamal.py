# -*- coding: utf-8 -*-
# AUTHOR: Soreat_u (2019-11-01)

'''
The ElGamal Public Key Cryptosystem implementation.
'''

import os
from random import randint
from Arithmetic import ModInverse as inverse


def PrikeyGen(pars):
    '''
    Private key creation.
    '''
    p = pars['p']
    a = int.from_bytes(os.urandom(p.bit_length()), 'big') % p
    return a

def PubkeyCreation(prikey, pars):
    '''
    Public key creation.
    '''
    g, p, a = pars['g'], pars['p'], prikey
    return pow(g, a, p)

def ElGamal_enc(m, pubkey, pars):
    '''
    Encryption of ElGamal.

    :param m: The message to be encrypted.
    :param pubkey: The public key.
    :param pars: The public parameters.
    :return: The cipher.
    :rtype: int
    '''
    g, p, A = pars['g'], pars['p'], pubkey
    k = randint(1, p-1)
    c1 = pow(g, k, p)
    c2 = m * pow(A, k, p) % p
    return (c1, c2)

def ElGamal_dec(c, prikey, pars):
    '''
    Decryption of ElGamal.

    :param c: The ciphertext to be decrypted.
    :param prikey: The private key.
    :param pars: The public parameters.
    :return: The messagetext.
    :rtype: int
    '''
    g, p, a = pars['g'], pars['p'], prikey
    c1, c2 = c[0], c[1]
    m = inverse(pow(c1, a, p), p) * c2 % p
    return m

def test():
    params = {
        'p': 467,
        'g': 2
    }
    prikey = 153
    m = 331
    
    pubkey = PubkeyCreation(prikey, params)
    c = ElGamal_enc(m, pubkey, params)
    print(f"Encryption: {c}")
    print(f"Decryption: {ElGamal_dec(c, prikey, params)}")

if __name__ == '__main__':
    test()