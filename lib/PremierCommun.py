import math
from termcolor import colored

def PremierCommun(N1,N2):
    p = math.gcd(N1,N2)
    q = N1 // p
    r = N2 // p
    assert (p*r == N2)
    assert (p*q == N1)
    print (colored(f"[+]Successfull factorized !","green"))
    print (colored(f"[+]for {N1}, p = {p} and q = {q}","yellow"))
    print (colored(f"[+]for {N2}, p = {p} and q = {r}","yellow"))


