import gmpy2
from Crypto.Util.number import *
from rich.console import Console

console = Console()

def egcd(a, b):
  if (a == 0):
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def neg_pow(a, b, n):
        assert b < 0
        assert GCD(a, n) == 1
        res = int(gmpy2.invert(a, n))
        res = pow(res, b*(-1), n)
        return res

def common_modulus(n,e1,e2,c1,c2):
        g, a, b = egcd(e1, e2)
        if a < 0:
                c1 = neg_pow(c1, a, n)
        else:
                c1 = pow(c1, a, n)
        if b < 0:
                c2 = neg_pow(c2, b, n)
        else:
                c2 = pow(c2, b, n)
        ct = c1*c2 % n
        m = int(gmpy2.iroot(ct, g)[0])
        console.print ("[bold red][*] Message Found ![/bold red]")
        console.print (f"[bold green]message = {m}[/bold green]")
        print (long_to_bytes(m))
        return m




