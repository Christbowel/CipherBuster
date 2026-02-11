"""
Fonctions mathématiques optimisées pour RSA
"""

import math
import gmpy2
from typing import Tuple, Optional


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Algorithme d'Euclide étendu
    Retourne (gcd, x, y) tel que a*x + b*y = gcd(a,b)
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)


def modinv(a: int, m: int) -> int:
    """
    Inverse modulaire : retourne x tel que (a * x) % m == 1
    """
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"L'inverse modulaire n'existe pas pour {a} mod {m}")
    return (x % m + m) % m


def isqrt(n: int) -> int:
    """
    Racine carrée entière (optimisée)
    """
    if n < 0:
        raise ValueError("La racine carrée d'un nombre négatif n'existe pas")
    if n < 2:
        return n
    
    # Utiliser gmpy2 si disponible (plus rapide)
    try:
        return int(gmpy2.isqrt(n))
    except:
        return int(math.isqrt(n))


def nth_root(x: int, n: int) -> Optional[int]:
    """
    Calcule la racine n-ième entière de x
    Retourne None si pas de racine entière exacte
    """
    if x == 0:
        return 0
    if x == 1:
        return 1
    if n == 1:
        return x
    
    # Recherche binaire
    upper = x
    lower = 0
    
    while upper - lower > 1:
        mid = (upper + lower) // 2
        mid_n = pow(mid, n)
        
        if mid_n == x:
            return mid
        elif mid_n < x:
            lower = mid
        else:
            upper = mid
    
    # Vérifier les candidats
    for candidate in [lower, upper, lower + 1]:
        if pow(candidate, n) == x:
            return candidate
    
    return None


def is_prime(n: int, trials: int = 20) -> bool:
    """
    Test de primalité Miller-Rabin
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    try:
        return gmpy2.is_prime(n, trials)
    except:
        # Fallback simple
        for i in range(2, min(int(math.sqrt(n)) + 1, 10000)):
            if n % i == 0:
                return False
        return True


def gcd(a: int, b: int) -> int:
    """
    Plus grand diviseur commun
    """
    try:
        return int(gmpy2.gcd(a, b))
    except:
        return math.gcd(a, b)


def chinese_remainder_theorem(remainders: list, moduli: list) -> int:
    """
    Théorème des Restes Chinois
    Résout le système x ≡ r_i (mod n_i)
    """
    total = 0
    prod = math.prod(moduli)
    
    for r_i, n_i in zip(remainders, moduli):
        p = prod // n_i
        inv = modinv(p, n_i)
        total += r_i * inv * p
    
    return total % prod