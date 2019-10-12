from cryptopals57.diffie_hellman import DiffieHellman
from functools import reduce
import random


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a * b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod


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


def attack(q, p, bob):
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


if __name__ == "__main__":
    p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
    g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
    q = 236234353446506858198510045061214171961

    B = DiffieHellman(g, p, q)
    B.generate_private_key()
    # B.private_key = 73499535754942345753719198372923258474
    B.generate_public_key()

    b_private_key = attack(q, p, B)
    if B.private_key == b_private_key:
        print("Good")
    else:
        print("Bad")
    print("B: {}".format(B.private_key))
    print("E: {}".format(b_private_key))
