# -*- coding: utf-8 -*-
# Written by *Soreat_u* on October 28th, 2019

'''
Pollard's ρ Method to solve the DLP over GF(p) in O(sqrt(N)) steps.
'''

from Arithmetic import LinearCongruenceSolver

def f(x, a, b, g, h, p):
    if 0 <= x <= p // 3:
        x = g * x % p
        a = (a+1) % (p-1)
    elif x <= 2 * p // 3:
        x = x * x % p
        a = 2 * a % (p-1)
        b = 2 * b % (p-1)
    else:
        x = h * x % p
        b = (b+1) % (p-1)
    return (x, a, b)


def DiscreteLog(g, h, p):
    '''
    Solve x such that g^x = h over GF(p).
    '''
    i, xi, yi = 0, 1, 1
    ai, bi, ci, di = 0, 0, 0, 0

    xi, ai, bi = f(xi, ai, bi, g, h, p)
    yi, ci, di = f(yi, ci, di, g, h, p)
    yi, ci, di = f(yi, ci, di, g, h, p)
    i += 1
    while xi != yi:
        xi, ai, bi = f(xi, ai, bi, g, h, p)
        yi, ci, di = f(yi, ci, di, g, h, p)
        yi, ci, di = f(yi, ci, di, g, h, p)
        i += 1
    
    u, v = (ai-ci) % (p-1), (di-bi) % (p-1)
    logs = LinearCongruenceSolver(v, u, p-1)
    for log in logs:
        if pow(g, log, p) == h:
            return (log, i)

def test():
    # quite slow...
    g, h, p = 6, 448509460363890, 1057584323171191
    x, i = DiscreteLog(g, h, p)
    print(f"{g}^{x} % {p} == {h} after {i} steps.")

if __name__ == '__main__':
    test()

