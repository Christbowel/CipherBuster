from factordb.factordb import FactorDB
from termcolor import colored

def factorisation(n):
   try:
      f = FactorDB(n)
      f.connect()
      result = f.get_factor_list()
      if (len(result) == 2):
         p = result[0]
         q = result[1]
         print(f"{n} success factorized, p = {p} and q = {q}")
      elif(len(result) >= 2):
         s = len(result)
         print ("success decomposed!")
         for i in range(s):
           print (f"{result[i]}")
      else:
         print (f"{n} can't be factorized !")


   except:
        print(colored("Failed to connect to the internet!","red"))


