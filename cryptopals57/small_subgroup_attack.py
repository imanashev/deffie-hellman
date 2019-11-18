from cryptopals57.diffie_hellman import DiffieHellman
from functools import reduce
import random


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a * b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod, prod


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1


def try_factorize(n, limit=2**16):
    primfac = []
    d = 2
    while d * d <= n and d < limit:
        while (n % d) == 0:
            primfac.append(d)
            n //= d
        d += 1
    return list(dict.fromkeys(primfac))


# h := rand(1, p)^((p-1)/r) mod p
def find_h(r, p):
    h = 1
    n = (p - 1) // r
    while h == 1:
        h = pow(int(random.randint(0, p)), n, p)
    return h


# K := h^x mod p
def brute_force(h, r, p, K):
    for x in range(r + 1):
        if K == pow(h, x, p):
            return x


def small_subgroup_attack(q, p, bob):
    j = (p - 1) // q
    factors = try_factorize(j)
    print("Process factors: {}".format(factors))
    secrets = []
    enough = 1
    for r in factors:
        print("    {}".format(r))
        h = find_h(r, p)

        bob.generate_session_key(h)
        K = bob.session_key
        x = brute_force(h, r, p, K)
        secrets.append(x)

        enough *= r
        if enough > q:
            break

    factors = factors[:len(secrets)]
    print("factors: {}".format(factors))
    print("secrets: {}".format(secrets))
    return chinese_remainder(factors, secrets)
