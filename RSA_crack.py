#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
    RSA Encryption, Decryption and Breaking
    By: Johan Hagg
    2011-05-06
    Tested on Python 2.7 and 3.2
    Last Updated: 2011-05-08
"""
import math
import random
import sys
import time

""" Converts n to it's binary number """
def denary_to_binary(n):
    bStr = ''
    if n < 0:
        raise(ValueError, "must be a positive integer")
    if n == 0:
        return '0'
    while n > 0:
        bStr = str(n % 2) + bStr
        n = n >> 1
    return bStr


""" Converts n into its binary number of length count """
def int_to_binary(n, count=16):
    if n == 0:
        return str(n) * count
    return "".join([str((n >> y) & 1) for y in range(count-1, -1, -1)])

""" Calculates the greatest common demnominator for x and y """
def GCD(x, y):
    if x < 0 : x = -x
    if y < 0 : y = -y

    if x+y > 0:
        g = y
        while x > 0:
            g = x
            x = y % x
            y = g
        return g
    else:
        return 0


""" Uses the extended euclidean algorithm on u and v """
def ext_euclid_alg(u, v):
    u1 = 1
    u2 = 0
    u3 = u
    v1 = 0
    v2 = 1
    v3 = v
    while v3 != 0:
        q = u3 / v3
        t1 = u1 - q * v1
        t2 = u2 - q * v2
        t3 = u3 - q * v3
        u1 = v1
        u2 = v2
        u3 = v3
        v1 = t1
        v2 = t2
        v3 = t3
    return u1, u2, u3

"""
    Computes the modular multiplicative inverse of a modulo m,
    using the extended Euclidean algorithm
"""
def mod_inv_euclid(a,m) :
    x,y,gcd = ext_euclid_alg(a,m)
    if gcd == 1 :
        return x % m
    else :
        return None

""" Computes x^c mod n more efficiently than math.pow(x,c)%n """
def square_and_multiply(x, c, n):
    bin_c = denary_to_binary(c)
    c_length = len(bin_c)
    z = 1
    for i in range(c_length, 0, -1):
        z = z ** 2 % n
        if int(bin_c[c_length - i]) == 1:
            z = (z * x) % n
    return z

""" Miller rabin pass returns True if n is probably a Prime, otherwise False """
def miller_rabin_pass(a, s, d, n):
    a_to_power = square_and_multiply(a, d, n)
    if a_to_power == 1:
        return True
    for i in range(s-1):
        if a_to_power == n-1:
            return True
        a_to_power = (a_to_power * a_to_power) % n
    return a_to_power == n - 1

""" Uses the miller rabin algorithm to determine wether n is a prime """
def miller_rabin(n):
    d = n - 1
    s = 0
    while d % 2 == 0:
        d >>= 1
        s += 1
    for repeat in range(100):
        a = 0
        while a == 0:
            a = random.randrange(n)
            if not miller_rabin_pass(a, s, d, n):
                return False
        return True

""" Generate a public key and a private key to be used in RSA encryption """
def generate_keys(lower, upper):
    p = 4
    q = 4
    while(miller_rabin(p) == False or miller_rabin(q) == False or (p == q)):
        if not miller_rabin(p):
            p = random.randint(lower, upper)
        if not miller_rabin(q):
            q = random.randint(lower, upper)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 2
    while(GCD(e, phi) != 1):
        e = random.randint(round(math.log(n,2)), phi)
    d = mod_inv_euclid(e, phi)
    public_key = (e, n)
    private_key = (d, n)
    return(public_key,private_key)

""" Encrypts m using RSA encryption, where e and n is the public key. """
def encrypt(m, e, n):
    return square_and_multiply(m, e, n)

""" Decrypts c using RSA decryption, where d and n is the private key. """
def decrypt(c, d, n):
    return square_and_multiply(c, d, n)

""" Generate r ciphertexts using public key (e,n) and RSA encryption """
def generate_ciphertexts(e, n, r):
    result = [0]
    for i in range(1, r):
        result.append(encrypt(i, e, n))
    return result

""" Find the message from m using generated cipher texts and r. """
def find_message(ciphertexts, m, n, r):
    for i in range(1, r):
        inv = mod_inv_euclid(ciphertexts[i], n)
        if inv != None:
            for j in range(1, r):
                if ciphertexts[j] == (m * inv) % n:
                    return (i * j) % n
    return None

""" Attempts to break RSA for small messages """
def break_rsa(m, n, e, r):
    r = 2 ** r
    return find_message(generate_ciphertexts(e,n,r), m, n, r)

""" Encodes character ch to binary notation of length 8 """
def encode_char(ch):
    return int_to_binary(ord(ch),8)

""" Decodes a binary number to a character """
def decode_char(b):
    return chr(int(b, 2))
                
def main():
    if len(sys.argv) < 2:
        print("Use the --help flag for instructions.")
        
    elif sys.argv[1] == "--keygen" and len(sys.argv) >= 4:
        public_key, private_key = generate_keys(int(sys.argv[2]), int(sys.argv[3]))
        print("Public Key (e, n)")
        print(public_key)
        print("Private Key (d, n)")
        print(private_key)

    elif sys.argv[1] == "--encrypt" and len(sys.argv) >= 5:
        word = sys.argv[4]
        e = int(sys.argv[2])
        n = int(sys.argv[3])
        text = ""
        for i in range(1, len(word)+1):
            text = text + encode_char(word[i - 1])
            if i % 2 == 0:
                text = int(text, 2)
                print(str(encrypt(text, e, n)))
                text = ""
        if text != "":
            if len(text) != 16:
                text = text + '0'*8
                text = int(text, 2)
                print(str(encrypt(text, e, n)))
            
    elif sys.argv[1] == "--decrypt" and len(sys.argv) >= 4:
        text = ""
        d = int(sys.argv[2])
        n = int(sys.argv[3])
        for line in sys.stdin:
            number = decrypt(int(line), int(sys.argv[2]), int(sys.argv[3]))
            number = str(int_to_binary(number, 16))
            text = text + decode_char(number[0:8]) + decode_char(number[8:16])
        print(text)
            
    elif sys.argv[1] == "--break" and len(sys.argv) >= 4:
        e = int(sys.argv[2])
        n = int(sys.argv[3])
        print("Public Key")
        print(e, n)
        result_string = ""
        tick = time.time()
        for line in sys.stdin:
            pick = break_rsa(int(line), n, e, int(sys.argv[4]))
            if pick != None:
                letters = int_to_binary(pick,16)
                result_string = result_string + chr(int(letters[0:8],2)) + chr(int(letters[8:16],2))
        print("Time taken: " + str(round(time.time()-tick, 2)) + " seconds.")
        print("Found message: " + result_string)

    elif sys.argv[1] == "--help":
        print("\nUse --keygen lower upper to generate a public and private key used to encrypt or decrypt a message, where lower and upper are bounds for the primes used in key generation.\n")
        print("Use --encrypt e n 'text' where n and d is part of the public key and text is the string to be encrypted.\n")
        print("Use --decrypt d n < file.txt  where n and d is part of the public key and file.txt is a file with RSA encoded strings.\n")
        print("Use --break r < file.txt  to break a encrypted file.\n")
    else:
        print("Faulty flag, use --help flag for instructions.")
main()
