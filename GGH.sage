# -*- codin: utf-8 -*-
# AUTHOR: Soreat_u (2020-02-05)

# Reference: Paper "Public-key cryptosystems from lattice reduction problems"

class GGH:
    '''
    GGH Cryptosystem Implementation.
    '''
    def __init__(self, n):
        self.n = n
        self.privkey, self.pubkey = self._generate(n)

    def set_keypair(self, R, B):
        self.privkey = R
        self.pubkey = B
        self.n = R.ncols()

    def encrypt(self, m, r=None, delta=3):
        if r == None:
            r = self._random_error_vector(self.n, delta)
        e = m*self.pubkey + r
        return e

    def decrypt(self, e):
        v = self._babais_algorithm(e)
        m = self.pubkey.solve_left(v)
        return m


    def _generate(self, n):
        l = 4
        k = round(sqrt(n)) * l
        I = matrix.identity(n)
        R = random_matrix(ZZ, n, n, x=-l, y=l+1)
        R = R + I*k

        B = R
        for _ in range(4):
            T = self._random_unimodular_matrix(n)
            B = T * B

        return R, B

    def _babais_algorithm(self, e):
        hRR = RealField(100)
        VV = MatrixSpace(hRR, self.n, self.n)(self.privkey)
        VV.solve_left(e)
        t = vector([int(round(i))  for i in VV.solve_left(e)])
        v = t * self.privkey
        return v

    def _random_unimodular_matrix(self, n):
        U = matrix(ZZ, n, n)
        for r in range(n):
            for j in range(r, n):
                if random() > 0.5:
                    U[r, j] = 1
                else:
                    U[r, j] = -1

        L = matrix(ZZ, n, n)
        for r in range(n):
            for j in range(r+1):
                if random() > 0.5:
                    L[r, j] = 1
                else:
                    L[r, j] = -1

        T = L*U
        return T

    def _random_error_vector(self, n, delta=3):
        r = vector(ZZ, n)
        for i in range(n):
            if random() > 0.5:
                r[i] = delta
            else:
                r[i] = -delta
        return r


def test():
    n = 100
    ggh = GGH(n)
    m = vector(ZZ, [i for i in range(n)])
    e = ggh.encrypt(m)
    assert(ggh.decrypt(e) == m)

if __name__ == "__main__":
    test()