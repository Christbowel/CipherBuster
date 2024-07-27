import gmpy2
from Crypto.Util.number import *
from factordb.factordb import FactorDB
import math
from rich.console import Console

from lib.FranklinReiter import FranklinReiter
from lib.ModuleCommun import common_modulus
from lib.PremierCommun import PremierCommun
from lib.PubkeyExtract import extract_public_key
from lib.RSAPrivateKey import PrivateKey
from lib.RSAdec import Encode,Decode
from lib.RSAfactorisation import factorisation
from lib.Wiener import wiener
from lib.pollar import PollardAttack
from termcolor import colored


console = Console()

def banner():
    banner = '''[bold cyan]
  ______      __           ___           __
 / ___(_)__  / /  ___ ____/ _ )__ _____ / /____ ____
/ /__/ / _ \/ _ \/ -_) __/ _  / // (_-</ __/ -_) __/
\___/_/ .__/_//_/\__/_/ /____/\_,_/___/\__/\__/_/    v1.0
     /_/
    [cyan]Creator:[/cyan][green] Christbowel[/green]

    '''
    console.print (banner)

def main():
    banner()
    desc = "This framework is a tool dedicated to exploiting vulnerabilities in RSA encryption."
    print (colored(desc,'yellow'))
    attack = '''
    1) Franklin-Reiter Attack
    2) Common Modulus Attack
    3) Simple Factorization Attack
    4) Wiener's Attack
    5) Simple RSA Encoding and Decoding
    6) Pollard's Rho Attack
    7) Public Key Parameters Extraction
    8) Common Prime Factor Attack
    9) Private Key Computation
    0) Exit
    '''

    print ("")
    print (colored(attack,"blue"))
    print ("")

    while True:
       try:
         choix = int(input("Enter a number: "))
         if (choix==1):
            print (colored("Franklin-Reiter Attack ........","magenta"))
            print (colored("Suppose there are two messages M1 and M2 where M1 != M2, both less than N and related to each other as equation [ M1 = f(M2) (mod N) ] for some linear polynomial equation [ f = ax + b ] where b!=0. These two messages are to be sent by encrypting using the public key (N, e), thus giving ciphertexts C1 and C2 respectively. Then, given (N, e, C1, C2, f), the attacker can recover messages M1 and M2","green"))
            N = gmpy2.mpz(int(input("Enter the value of N: ")))
            e = gmpy2.mpz(int(input("Enter the value of e: ")))
            C1 = gmpy2.mpz(int(input("Enter the value of the first Cipher (C1): ")))
            C2 = gmpy2.mpz(int(input("Enter the value of the second cipher (C2): ")))
            a = gmpy2.mpz(int(input("Enter the value of a in the linear function: ")))
            b = gmpy2.mpz(int(input("Enter the value of b in the linear function: ")))
            m1, m2 = FranklinReiter(N,e,C1,C2,a,b)
            print (f"[*] RESULT :")
            print (colored(f"[+] M1 = {m1}","green"))
            print (colored(f"[+] M2 = {m2}", "green"))
            exit()

         elif (choix==2):
            print (colored("Common Modulus Attack ........","magenta"))
            print (colored("This attack specifically targets the potential weakness of RSA encryption by exploiting relationships between ciphertexts encrypted with different exponents but the same modulus, compromising the security of the system","green"))
            print ("")
            n = int(input("Enter the value of N: "))
            e1 = int(input("Enter the first value of e: "))
            e2 = int(input("Enter the second value of e: "))
            c1 = int(input("Enter the first value of the Cipher: "))
            c2 = int(input("Enter the second value of the Cipher: "))
            console.print (f"[*][bold yellow]RESULT : {common_modulus(n,e1,e2,c1,c2)}[/bold yellow]")
            exit()

         elif (choix==3):
            print (colored("Simple Factorization Attack ........","magenta"))
            print (colored("This attack targets RSA encryption by exploiting the difficulty of factoring large prime numbers used in generationg public and private keys","green"))
            n = int(input("Enter the value of n: "))
            print (input(colored("To launch this attack, ensure that you are connected to the internet!","red"))) 
            factorisation(n)
            exit()

         elif (choix==4):
            print (colored("Wiener's Attack ........","magenta"))
            print (colored("This attack specifically targeting systems where the private key d is too small relative to the modulus n, compromising security by allowing the recovery of the private key.","green"))
            n = int(input("Enter the value of N: "))
            e = int(input("Enter the value of e: "))
            d = wiener(n,e)
            if d:
                print(f"[bold green][+] FOUND d = {d}[/bold green]")
            else:
                print(colored("Failed!", "red"))
            exit()

         elif (choix==5):
            print (colored("Simple RSA Encoding and Decoding ......","magenta"))
            print (colored("This attack ","yellow"))
            print ("Select a choice: ")
            choices = '''
      1: Encode
      2: Decode
            '''
            print (colored(choices,"blue"))
            choice = int(input(">>>"))
            if (choice ==1):
               e = int(input("Enter the value of e: "))
               n = int(input("Enter the value of n: "))
               m = int(input("Enter the value of the message as long: "))
               Encode(e,n,m)
               break

            elif (choice == 2):
               c = int(input("Enter the value of the CipherText as long: "))
               n = int(input("Enter the value of n: "))
               d = int(input("Enter the value of the PrivateKey (d): "))
               Decode(c,n,d)
               break

            else:
               console.print ("[bold red]Invalid Option![/bold red]")
               console.print("\n[bold yellow]Bye Bye H4x0R !!![/bold yellow]")
               exit()

         elif (choix==6):
              print (colored("Pollard's Rho Attack ......","magenta"))
              print (colored("This attack ","yellow"))
              B = int(input("Enter the value of B (2 by default): "))
              N = int(input("Enter the value of N: "))
              PollardAttack(B,N)
              break

         elif (choix==7):
              print (colored("Public Key Parameters Extraction ......","magenta"))
              print (colored("This attack ","yellow"))
              filename = input("Enter the path of the Public Key File: ")
              n, e = extract_public_key(filename)
              while True:
                  print (colored(f"[+] N = {n}","green"))
                  print (colored(f"[+] E = {e}", "green"))
                  break

         elif (choix==8):
              print (colored("Common Prime Factor Attack ......","magenta"))
              print (colored("This attack ","yellow"))
              N1 = int(input("Enter the first value of N: "))
              N2 = int(input("Enter the second value of N: "))
              PremierCommun(N1,N2)
              break

         elif (choix==9):
              print (colored("Private Key Computation ......","magenta"))
              print (colored("This attack ","yellow"))
              p = int(input("Enter the value of p >> "))
              q = int(input("Enter the value of q >> "))
              e = int(input("Enter the value of e >> "))
              d = PrivateKey(p,q,e)
              console.print (f"[bold green]Succesfull retrieved, d = {d} [/bold green]")
              break


       except KeyboardInterrupt:
             console.print("\n[bold yellow]Bye Bye H4x0R !!![/bold yellow]")
             break





if __name__=="__main__":
   main()
