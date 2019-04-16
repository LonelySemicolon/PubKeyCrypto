#Benjamin Baleilevuka
#CS485, Cryptography
#Project 2, Public Key Crypto
#Sarah Mocas, Crypto Professor

import random
import binascii



def split(str, num):
    return [ str[start:start+num] for start in range(0, len(str), num) ]

def getPrime():
  #k is the number of bits being used
  k = 32
  seedNum = input("Please enter a seed value: ")
  print("Seed number: " + seedNum)

  #seed the random generator
  random.seed(seedNum)
  
  #give q a random number of size k bits
  q = random.getrandbits(k)

  #loop to check if the number generated is prime, and if
  #its leading bit is on
  while(not(is_prime(q)) or (1 & (q >> (k-1)) != 1)):
    q = random.getrandbits(k)

    #if this prime mod by 12 is not 5
    #multiple by 2, making it a non-prime
    if((q % 12) != 5):
      q = q * 2
    else:
      #generate the p value and check if its prime
      q = ((2 * q) + 1)

  return q


#Modulo Exponentiation taken from 
#https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
def power(x, y, p):
  res = 1

  x = x % p
  while (y > 0):

    if((y & 1) == 1):
      res = (res * x) % p

    y = y >> 1
    x = (x * x) % p
  return res


#Prime testing, Miller-Rabin, take from
#https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#Python
def _try_composite(a, d, n, s):
    if pow(a, d, n) == 1:
        return False
    for i in range(s):
        if pow(a, 2**i * d, n) == n-1:
            return False
    return True # n  is definitely composite
 
def is_prime(n, _precision_for_huge_n=16):
    if n in _known_primes:
        return True
    if any((n % p) == 0 for p in _known_primes) or n in (0, 1):
        return False
    d, s = n - 1, 0
    while not d % 2:
        d, s = d >> 1, s + 1
    # Returns exact according to http://primes.utm.edu/prove/prove2_3.html
    if n < 1373653: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3))
    if n < 25326001: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5))
    if n < 118670087467: 
        if n == 3215031751: 
            return False
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7))
    if n < 2152302898747: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11))
    if n < 3474749660383: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13))
    if n < 341550071728321: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13, 17))
    # otherwise
    return not any(_try_composite(a, d, n, s) 
                   for a in _known_primes[:_precision_for_huge_n])
 
_known_primes = [2, 3]
_known_primes += [x for x in range(5, 1000, 2) if is_prime(x)]


def main():
  userInput = "0"
  while(userInput != "4"):
    userInput = input("Do you want to\n(1) Setup public Keys\n(2) Encrypt\n(3) Decrypt\n(4) Exit\n")
    if(userInput == "1"):
      #function to get a large p of 32 bits
      p = getPrime()
      print("getPrime = " + str(p))
    
      #Get a private key from the user
      d = int(input("enter a private key\n"))

      #Calculate e2 for public key
      e2 = power(2, d, p)
      print("Public Key(p,g,e2)\n(" + str(p) + ", " + "2" + ", " + str(e2) + ")\nin pubkey.txt and private key in prikey.txt")


      #Write public key to text file---------------------#
      #--------------------------------------------------#
      file = open("pubkey.txt", "w")

      file.write(str(p) + " " + str(2) + " " + str(e2))

      file.close()
      #--------------------------------------------------#

      #write private key to text file--------------------#
      #--------------------------------------------------#
      file = open("prikey.txt", "w")

      file.write(str(p) + " " + str(2) + " " + str(d))

      file.close()
      #--------------------------------------------------#

    #Encrypte the message using public Keys
    if(userInput == "2"):
      with open("pubkey.txt", "r") as f:
        pubKey = f.readline().split(' ')

      p = int(pubKey[0])
      g = int(pubKey[1])
      e2 = int(pubKey[2])

      userIn = split(input("Type a message and press enter\n"), 4)

      c2 = 0

      print(userIn)
      f = open('ctext.txt', 'w')
      for c in userIn:
        #convert from string to integer
        c2 = (int.from_bytes(c.encode(), byteorder='big'))
        rand = random.randint(0, p-2)
        c1 = power(2, rand, p)
        #print("rand: ", rand, "\nc1: ", c1, " BitLength = ", c2.bit_length())
        c2 = (((c2 % p) * power(e2, rand, p)) % p)
        #print("c2: ", c2, " BitLength = ", c2.bit_length())
        f.write(str(c1) + " ")
        f.write(str(c2) + "\n")
        c2 = 0
      f.close()

    #Decrypt the message with private keys
    if(userInput == "3"):
      secret = ""
      keys = open('prikey.txt', 'r')
      priKeys = keys.readline().split(' ')
      keys.close()
      p = int(priKeys[0])
      g = int(priKeys[1])
      d = int(priKeys[2])
      f = open('ctext.txt', 'r')
      for line in f:
        cText = line.split(' ')
        #print(cText)
        c1 = int(cText[0])
        c2 = int(cText[1])
        message = ((power(c1, (p - 1 - d), p) * (c2 % p)) % p)
        print("c1 ", c1, " c2 ", c2, " message: ", message)
        message = message.to_bytes(message.bit_length(), byteorder='big')
        message = message.decode('ascii')
        print(message)
        secret += message
      f.close()

      #Decrypted message printed to the screen
      print("\nDecrypted Message:\n\n" + secret + "\n")

      with open('ptext.txt', 'w') as f:
        f.write(secret)




























if __name__ == '__main__':
  main()
