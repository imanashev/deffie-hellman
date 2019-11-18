from cryptopals57.diffie_hellman import DiffieHellman
from cryptopals57.small_subgroup_attack import small_subgroup_attack


if __name__ == "__main__":
    p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
    g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
    q = 236234353446506858198510045061214171961

    B = DiffieHellman(g, p, q)
    B.generate_private_key()
    # B.private_key = 73499535754942345753719198372923258474
    B.generate_public_key()

    b_private_key = small_subgroup_attack(q, p, B)[0]
    if B.private_key == b_private_key:
        print("Good")
    else:
        print("Bad")
    print("B: {}".format(B.private_key))
    print("E: {}".format(b_private_key))
