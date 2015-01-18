# Stanford University
# Cryptography I
# https://www.coursera.org/course/crypto

# Week 2
# Question 5
# Nonce-based CBC. Recall that in lecture 4.4 we said that if one wants to use CBC encryption with a non-random unique nonce then the nonce must first be encrypted with an independent PRP key and the result then used as the CBC IV. Let's see what goes wrong if one encrypts the nonce with the same PRP key as the key used for CBC encryption. 

# Let F:Kx{0,1}l->{0,1}l be a secure PRP with, say, l=128. Let n be a nonce and suppose one encrypts a message m by first computing IV=F(k,n)
# and then using this IV in CBC encryption using F(k,.). 
# Note that the same key k is used for computing the IV and for CBC encryption. We show that the resulting system is not nonce-based CPA secure. 

# The attacker begins by asking for the encryption of the two block message m=(0l,0l) with nonce n=0l. It receives back a two block ciphertext (c0,c1). Observe that by definition of CBC we know that c1=F(k,c0). Next, the attacker asks for the encryption of the one block message m1=c0 xor c1 with nonce n=c0. It receives back a one block ciphertext c'0. 

# What relation holds between c0,c1,c'0?   Note that this relation lets the adversary win the nonce-based CPA game with advantage 1.
# c0=c1 xor c'0
# c1=c0
# c1=0l
# c1=c'0



import sys
import numpy
from operator import methodcaller


def main():
	key = hexStrToInt("1a2b3c4d")

	# loop 1
	zero = hexStrToInt("00000000")
	m0Arr = [zero, zero]
	n0 = encrypt(key, zero)

	c0Arr = cbc(key, n0, m0Arr)



	# loop 2
	m1Arr = [c0Arr[0] ^ c0Arr[1]]
	n1 = c0Arr[0]

	c1Arr = cbc(key, n1, m1Arr)	

	
	c0 = int(c0Arr[0])
	c1 = int(c0Arr[1])
	c_0 = int(c1Arr[0])
	# result
	print "c0 = %s" % intToHexStr(c0), c0
	print "c1 = %s" % intToHexStr(c1), c1
	print "c'0 = %s" % intToHexStr(c_0), c_0

	

	print "\n\n"
	print "c0=c1 xor c'0 ? => %s = %s xor %s => %s" % (intToHexStr(c0), intToHexStr(c1), intToHexStr(c_0), (c1 ^ c_0 == c0) )
	print "c1=c0 ? => %s = %s  => %s" % (intToHexStr(c1), intToHexStr(c0),  (c1 == c0) )
	print "c1=0^l ? => %s = %s  => %s" % (intToHexStr(c1), intToHexStr(zero),  (c1 == zero) )
	print "c1=c'0 ? => %s = %s  => %s" % (intToHexStr(c1), intToHexStr(c_0),  (c1 == c_0) )


	# c0 = 00607c3c 6323260
	# c1 = 0859b203 140096003
	# c'0 = 0040f858 4257880



	# c0=c1 xor c'0 ? => 00607c3c = 0859b203 xor 0040f858 => False
	# c1=c0 ? => 0859b203 = 00607c3c  => False
	# c1=0^l ? => 0859b203 = 00000000  => False
	# c1=c'0 ? => 0859b203 = 0040f858  => False
	
	# @todo ??? Doing something wrong.. but what???

	

def cbc(k, iv, mArray):
	cArray = []
	lastInp = iv
	for m in mArray:
		inp = lastInp ^ m
		c = encrypt(k, inp)
		cArray.append(c)
		lastInp = c
	return cArray

	

def encrypt(k, i):
	return (i  + k )


def hexStrToInt(s):
	return int(s, 16)

def intToHexStr(i):
	return hex(i)[2:].zfill(8)


main()