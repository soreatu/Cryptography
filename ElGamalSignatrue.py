#!/usr/bin/env python3
import os
from random import SystemRandom
from hashlib import sha256

from Crypto.Util import number

random = SystemRandom()

def genkey(params):
    p = params['p']
    g = params['g']

    x = random.randint(1, p-2)
    y = pow(g, x, p)

    return (y, x)

def sign(m, params, prikey):
    p = params['p']
    g = params['g']
    x = prikey

    k = random.randint(1, p-1)
    while number.GCD(k, p-1) != 1:
        k = random.randint(1, p-1)

    Hm = int.from_bytes(sha256(m.encode()).digest(), 'big')

    r = pow(g, k, p)
    s = (number.inverse(k, p-1) * (Hm - x*r)) % (p - 1)
    return (r, s)

def verify(m, sig, params, pubkey):
    r, s = sig
    p = params['p']
    g = params['g']
    y = pubkey

    if not (0 < r < p) or not (0 < s < p):
        return False

    Hm = int.from_bytes(sha256(m.encode()).digest(), 'big')
    l = pow(g, Hm, p)
    r = (pow(y, r, p) * pow(r, s, p)) % p

    return l == r


def test():
    params = {
        # Parameters chosen from RFC3526 (https://www.ietf.org/rfc/rfc3526.txt)
        "p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
        "g": 2
    }
    pubkey, prikey = genkey(params)
    print(f"params: {params}")
    print(f"public key: {pubkey}")
    print(f"private key: {prikey}")

    message = "The quick brown fox jumps over the lazy dog"
    signature = sign(message, params, prikey)

    print(f"Sending message: {message}")
    print(f"Signature: {signature}")

    print(f"Verify: {verify(message, signature, params, pubkey)}")

if __name__ == "__main__":
    test()