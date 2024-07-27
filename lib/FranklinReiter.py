import gmpy2

theorem= "Suppose there are two messages M1 and M2 where M1 != M2, both less than N and related to each other as equation [ M2 = f(M1) (mod N) ] for some linear polynomial equation [ f = ax + b ] where b!=0. These two messages are to be sent by encrypting using the public key (N, e), thus giving ciphertexts C1 and C2 respectively. Then, given (N, e, C1, C2, f), the attacker can recover messages M1 and M2"

def FranklinReiter(n, e, c1, c2, a, b):
    print (theorem)
    for possible_m1 in range(0, n):
        if gmpy2.powmod(possible_m1, e, n) == c1:
            possible_m2 = a * possible_m1 + b
            if gmpy2.powmod(possible_m2, e, n) == c2:
                return possible_m1, possible_m2

    raise ValueError("Les messages m1 et m2 n'ont pas été trouvés")



