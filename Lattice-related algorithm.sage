# -*- codin: utf-8 -*-
# AUTHOR: Soreat_u (2020-02-04)

def HadamardRatio(B):
    '''
    INPUT:

    * "B" -- a matrix representation of a lattice.

    OUTPUT:

    * "H" -- a real number between 0 and 1.

    The closer that the value is to 1, the more orthogonal are the vectors
    in the basis.

    '''
    n = L.ncols()
    H = (abs(B.det()) / product(v.norm() for v in B))^(1/n)
    return H

def GramSchmidtAlgorithm(M):
    '''
    Given a basis for a vector space $V \in R^m$, creates
    an orthogonal basis for $V$.

    INPUT:

    * "M" -- a matrix.

    OUTPUT:

    * "G" -- a matrix consisting of vectors that are pairwise orthogonal.

    NOTE:

    Better way to do this -- sage: G, _ = M.gram_schmidt()

    '''
    n = M.nrows()
    G = matrix(RR, n)
    for i in range(n):
        vi = M[i]
        for j in range(i):
            mu = (M[i]*G[j]) / G[j].norm()^2
            vi -= mu * G[j]
        G[i] = vi
    return G

def BabaisClosestVertexAlgorithm(L, w):
    '''
    INPUT:

    * "L" -- a matrix representing the reduced basis (v1, ..., vn) of a lattice.

    * "w" -- a target vector to approach to.

    OUTPUT:

    * "v" -- a approximate closest vector.

    '''
    vt = L.solve_left(w)
    v = vector(ZZ, [0]*len(L[0]))
    for t, vi in zip(vt, L):
        v += round(t) * vi
    return v

def BabaisClosestPlaneAlgorithm(L, w):
    '''
    Yet another method to solve apprCVP, using a given good basis.

    INPUT:

    * "L" -- a matrix representing the reduced basis (v1, ..., vn) of a lattice.

    * "w" -- a target vector to approach to.

    OUTPUT:

    * "v" -- a approximate closest vector.

    Quoted from "An Introduction to Mathematical Cryptography":
    In both theory and practice, Babai's closest plane algorithm
    seems to yield better results than Babai's closest vertex algorithm.

    '''
    G, _ = L.gram_schmidt()
    t = w
    i = L.nrows() - 1
    while i >= 0:
        w -= round( (w*G[i]) / G[i].norm()^2 ) * L[i]
        i -= 1
    return t - w

def GaussianHeuristic(L):
    '''
    Calculates the Gaussian expected shortest length.

    INPUT:

    * "L" -- a matrix representation of a lattice with small dimension.

    OUTPUT:

    * “sigma" -- a positive real number.

    '''
    n = L.ncols()
    sigma = (gamma(1 + n/2) * abs(L.det()))^(1/n) / sqrt(pi)
    return sigma

def LLL(L, delta=0.75):
    '''
    The LLL Lattice Reduction Algorithm.

    INPUT:

    * "L" -- a matrix representing a lattice basis.

    * "delta" -- a constant between 0.25 and 1.

    OUTPUT:

    * "Q" -- a matrix which is LLL-reduced.

    NOTE:

    Better way to do this -- sage: L.LLL(delta=0.75)

    '''

    Q = matrix(ZZ, L)
    G, M = Q.gram_schmidt()

    k = 1
    n = Q.nrows()

    while k < n:
        # Size Reduction
        for j in reversed(range(k-1)):
            Q[k] = Q[k] - round(M[k,j])*Q[j]
            G, M = Q.gram_schmidt()

        # Lovasz Condition
        if G[k].norm()^2 >= (delta - M[k,k-1]^2) * G[k-1].norm()^2:
            k = k + 1
        else:
            # Swap Step
            Q[k], Q[k-1] = Q[k-1], Q[k]
            G, M = Q.gram_schmidt()
            k = max(k-1, 1)

    return Q
