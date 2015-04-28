# Question 1
# An attacker intercepts the following ciphertext (hex encoded): 

#    20814804c1767293b99f1d9cab3bc3e7 ac1e37bfb15599e5f40eef805488281d 

# He knows that the plaintext is the ASCII encoding of the message "Pay Bob 100$" (excluding the quotes). 
# He also knows that the cipher used is CBC encryption with a random IV using AES as the underlying block cipher. 
# Show that the attacker can change the ciphertext so that it will decrypt to "Pay Bob 500$". What is the resulting ciphertext (hex encoded)? 
# This shows that CBC provides no integrity.

import sys

def main():
	# input
	cypherText = "20814804c1767293b99f1d9cab3bc3e7 ac1e37bfb15599e5f40eef805488281d".split(' ')
	
	# set the CBC parts. The first part is the IV
	cypherTextIV = cypherText[0].decode('hex')
	cypherTextC0 = cypherText[1].decode('hex')
	
	# define plaintexts
	plainText = "Pay Bob 100$"
	plainTextTarget = "Pay Bob 500$"

	# define paddings
	paddingNum1 = str(len(cypherTextC0) - len(plainText))
	padding1 = "".join([paddingNum1] * int(paddingNum1))

	paddingNum2 = str(len(cypherTextC0) - len(plainTextTarget))
	padding2 = "".join([paddingNum2] * int(paddingNum2))

	# append to plaintext the paddings
	plainText += padding1
	plainTextTarget += padding2

	# XOR the plaintext to determine the value to XOR with
	xorredPlainText = strxor(plainText, plainTextTarget)

	# Since the decription of c[0] is XORed with IV to retrieve the plaintext xor the IV with the desired mutation
	newIV = strxor(xorredPlainText, cypherTextIV)

	# new CBC 
	print "New CBC\n",newIV.encode('hex'), cypherText[1]

	# Output:
	# New CBC
	# 20814804c1767293bd9f1d9cab3bc3e7 ac1e37bfb15599e5f40eef805488281d


# xor two strings of different lengths
def strxor(a, b):     
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


main()