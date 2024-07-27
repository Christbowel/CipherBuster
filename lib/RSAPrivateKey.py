def PrivateKey(p,q,e):
    phi = (p-1)*(q-1)
    d = pow(e,-1,phi)
    return d
