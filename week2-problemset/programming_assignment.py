# Stanford University
# Cryptography I
# https://www.coursera.org/course/crypto

# Week 2
# Question 1-4


# In this project you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES in counter mode (CTR). In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext. For CBC encryption we use the PKCS5 padding scheme discussed in class (13:50). 
# While we ask that you implement both encryption and decryption, we will only test the decryption function. In the following questions you are given an AES key and a ciphertext (both are hex encoded) and your goal is to recover the plaintext and enter it in the input boxes provided below. 

# For an implementation of AES you may use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), or any other. While it is fine to use the built-in AES functions, we ask that as a learning experience you implement CBC and CTR modes yourself. 

import sys
from operator import methodcaller
import re
import numpy
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random

def main():
	blockSize = 16 # 16-byte encryption
	q1 = cbcDecrypt("140b41b22a29beb4061bda66b6747e14", "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", blockSize)	
	q2 = cbcDecrypt("140b41b22a29beb4061bda66b6747e14", "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253", blockSize)	
	q3 = ctrDecrypt("36f18357be4dbd77f050515c73fcf9f2", "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329", blockSize)	
	q4 = ctrDecrypt("36f18357be4dbd77f050515c73fcf9f2", "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451", blockSize)	
	
	print "\n\nAnswers:"
	print "Q1. ",q1
	print "Q2. ",q2
	print "Q3. ",q3
	print "Q4. ",q4

	#Result
	# CBC decryption of key/cypher 140b41b22a29beb4061bda66b6747e14  /  4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81
	# 1:  Basic CBC mode encryption needs padding.
	# 2:  Basic CBC mode encryption needs padding.

	# CBC decryption of key/cypher 140b41b22a29beb4061bda66b6747e14  /  5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253
	# 1:  Our implementation uses rand. IV
	# 2:  Our implementation uses rand. IV

	# CTR decryption of key/cypher 36f18357be4dbd77f050515c73fcf9f2  /  69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329
	# 1:  CTR mode lets you build a stream cipher from a block cipher.
	# 2:  ?

	# CTR decryption of key/cypher 36f18357be4dbd77f050515c73fcf9f2  /  770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451
	# 1:  Always avoid the two time pad!
	# 2:  ?


	# Answers:
	# Q1.  Basic CBC mode encryption needs padding.
	# Q2.  Our implementation uses rand. IV
	# Q3.  CTR mode lets you build a stream cipher from a block cipher.
	# Q4.  Always avoid the two time pad!


# Do 2 variants of CTR decryption  	
def ctrDecrypt(key, cypherText, blockSize):
	print "\nCTR decryption of key/cypher",key," / ",cypherText
	res1 = ctrDecrypt1(key, cypherText, blockSize)
	res2 = ctrDecrypt2(key, cypherText, blockSize)
	print "1: ", res1 
	print "2: ", res2
	return res1

# CTR decryption variant 1 (use AES.MODE_CBC mode), 
def ctrDecrypt1(key, cypherText, blockSize):
	k = key.decode('hex')
	ct = cypherText.decode('hex')
	iv = ct[:blockSize]
	ct1 = ct[blockSize:]
	ctr = Counter.new(blockSize*8,initial_value=long(iv.encode('hex'),16))
	obj = AES.new(k,AES.MODE_CTR,counter=ctr)
	paddedStr = obj.decrypt(ct1)
	#paddingAmount = ord(paddedStr[len(paddedStr)-1:])
	return paddedStr#[:-paddingAmount]

# CTR decryption variant 2 
def ctrDecrypt2(key, cypherText, blockSize):
	cypherTextBlocks =  [cypherText[i:i+(blockSize*2)] for i in range(0, len(cypherText), (blockSize*2))]	
	iv =  long(cypherTextBlocks.pop(0), 16) 

	cypherTextBlocksDecoded = map(methodcaller("decode", "hex"), cypherTextBlocks)
	
	k = key.decode('hex')

	pt = ""

	i = 0
	for c in cypherTextBlocksDecoded:
	 	ctr = hex(iv+i << 64)[2:(2*blockSize)+2]
	 	#print ctr
	 	encIV = AES.new(k, AES.MODE_ECB).encrypt(ctr)	
	 	plaintext =  strxor(encIV, c)
	 	#print plaintext
	  	i = i + 1
	  	pt = plaintext + pt
	
	# @todo something is wrong with this implementation		
	return "?"#pt
  
# Do 2 variants of CBC decryption  	
def cbcDecrypt(key, cypherText, blockSize):
	print "\nCBC decryption of key/cypher",key," / ",cypherText
	res1 = cbcDecrypt1(key, cypherText, blockSize)
	res2 = cbcDecrypt2(key, cypherText, blockSize)
	print "1: ", res1 
	print "2: ", res2
	return res2

# CBC decryption variant 1 (use AES.MODE_CBC mode), 
def cbcDecrypt1(key, cypherText, blockSize):
	k = key.decode('hex')
	ct = cypherText.decode('hex')
	iv = ct[:blockSize]
	ct1 = ct[blockSize:]
	obj = AES.new(k,AES.MODE_CBC,iv)
	paddedStr = obj.decrypt(ct1)
	paddingAmount = ord(paddedStr[len(paddedStr)-1:])
	return paddedStr[:-paddingAmount]


# CBC decryption variant 2 defines blocks self, encrypts per block (ECB mode) and xors with previous block => plaintext
def cbcDecrypt2(key, cypherText, blockSize):
	cypherTextBlocks =  [cypherText[i:i+(blockSize*2)] for i in range(0, len(cypherText), (blockSize*2))]
	cypherTextBlocksDecoded = map(methodcaller("decode", "hex"), cypherTextBlocks)
	#iv =  cypherTextBlocksDecoded.pop(0)
	k = key.decode('hex')

	pt = ""

	iter = len(cypherTextBlocksDecoded)
	for c in reversed(cypherTextBlocksDecoded):
		iter = iter - 1
		if(iter > 0):
			cipher = AES.new(k, AES.MODE_ECB).decrypt(c)			
			plaintext = strxor(cipher, cypherTextBlocksDecoded[iter - 1])
			#print "[",iter,"]", c.encode('hex'), " => ", cipher.encode('hex'), plaintext
			pt = plaintext + pt

	paddingAmount = ord(pt[len(pt)-1:])
			
	return pt[:-paddingAmount]


# xor two strings of different lengths
def strxor(a, b):     
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

main()
	

