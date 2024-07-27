import sympy

def wiener(n, e):
    fraction = sympy.continued_fraction(sympy.Rational(e, n))
    for convergent in fraction:
        k, d = convergent.numerator, convergent.denominator
        if d > 0 and e * d % n == 1:
            return d
    return None

