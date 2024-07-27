from Crypto.Util.number import *
from termcolor import colored

def Encode(e,n,m):
    c = pow(m,e,n)
    print (f"the CipherText is {c}")


def Decode(c,n,d):
    m = pow(c,d,n)
    print (f"The Original message is {m}")
    try:
       print (str(long_to_bytes(m).decode("utf-8")))
    except:
       print(colored("Failed to decode !!!","red"))


