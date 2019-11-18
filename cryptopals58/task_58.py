from cryptopals58.pollards_kangaroo import pollards_kangaroo
from cryptopals57.diffie_hellman import DiffieHellman
from cryptopals57.small_subgroup_attack import small_subgroup_attack, mul_inv


if __name__ == "__main__":
    p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
    q = 335062023296420808191071248367701059461
    j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
    g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357
    y = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
    # 705485
    # y = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733
    # 359579674340
    # print(pollards_kangaroo(g, p, y, lower_bound=0, upper_bound=2**20))
    # exit(0)

    bob = DiffieHellman(g, p, q)
    bob.generate_private_key()
    # bob.private_key = 73499535754942345753719198372923258474
    # bob.private_key = 59218903646839673978326597577070215555
    bob.generate_public_key()
    y = bob.public_key

    ssa_n, ssa_r = small_subgroup_attack(q, p, bob)
    # print(ssa_n, ssa_r)
    # ssa_n, ssa_r = 25793, 63803

    lower_bound = 0
    upper_bound = (q - 1) // ssa_r
    # print("upper_bound: {}".format(upper_bound))

    # print(ssa_n)
    # print(mul_inv(ssa_n, p))
    # print(p)

    # y_new = y * pow(g, mul_inv(ssa_n, p), p) % p
    # g_new = pow(g, ssa_r, p)
    # y_new = y * pow(mul_inv(g, p), ssa_n, p) % p
    # g_new = pow(g, ssa_r, p)
    # y_new = y * pow(mul_inv(g, p), ssa_n, p) % p
    y_new = y * mul_inv(pow(g, ssa_n, p), p) % p
    g_new = pow(g, ssa_r, p)

    m = pollards_kangaroo(g_new, p, y_new, lower_bound, upper_bound)
    if m is None:
        exit(1)
    key = ssa_n + m * ssa_r

    print(key)
    # x = n mod r
    # [0, (q-1)/r]

    # x = n + m*r
    #     y = g^x = g^(n + m*r)
    #     y = g^n * g^(m*r)
    #     y' = y * g^-n = g^(m*r)
    #     g' = g^r
    #     y' = (g')^m

