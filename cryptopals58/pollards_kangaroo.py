from statistics import mean
from math import log


def pollards_kangaroo(generator, prime, y, lower_bound, upper_bound, range_constant=4):
    def next_step(n):
        return pow(2, n % leap_range)  # mod p

    def next_value(n):
        return (n * pow(generator, next_step(n), prime)) % prime

    leap_range = int(log(upper_bound - lower_bound) / log(range_constant))
    n = range_constant * pow(2, leap_range - 1) // leap_range

    tame_x = 0
    tame_y = pow(generator, upper_bound, prime)
    for _ in range(n):
        tame_x += next_step(tame_y)
        tame_y = next_value(tame_y)

    wild_x = 0
    wild_y = y
    while wild_x < (upper_bound - lower_bound + tame_x):
        wild_x += next_step(wild_y)
        wild_y = next_value(wild_y)
        # print(".", end="")
        if wild_y == tame_y:
            return (upper_bound + tame_x - wild_x) % prime
