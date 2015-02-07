# Question 8
# In this question and the next, you are asked to find collisions on two compression functions:
# f1(x,y)=AES(y,x) xor y,  and
# f2(x,y)=AES(x,x) xor y,
# where AES(x,y) is the AES-128 encryption of y under key x. 

# We provide an AES function for you to play with. The function takes as input a key k and an x value and outputs AES(k,x) once you press the "encrypt" button. 
# It takes as input a key k and a y value and outputs AES-1(k,y) once you press the "decrypt" button. All three values k,x,y are assumed to be hex values (i.e. using only characters 0-9 and a-f) and the function zero-pads them as needed. 

# Your goal is to find four distinct pairs (x1,y1),  (x2,y2),  (x3,y3),  (x4,y4) such that f1(x1,y1)=f1(x2,y2) and f2(x3,y3)=f2(x4,y4). In other words, the first two pairs are a collision for f1 and the last two pairs are a collision for f2. Once you find all four pairs, please enter them below and check your answer using the "check" button.
# Note for those using the NoScript browser extension: for the buttons to function correctly please allow Javascript from class.coursera.org and cloudfront.net to run in your browser. Note also that the "save answers" button does not function for this question and the next.


import sys
from Crypto.Cipher import AES


# Please find (x1,y1), (x2,y2) such that f1(x1,y1)=f1(x2,y2).
# => AES(y1,x1) xor y1 = AES(y2,x2) xor y2
# Unsing E for encrypt, D for decrypt:
# => E(y1,x1) xor y1 = E(y2,x2) xor y2

# Finding a flaw in AES seemed a bit too extreme for a homework assignment, so I assume message x2 is f1(x1,y1), decrypted by y2
# => E(y1,x1) xor y1 = E(y2, D(y2, E(y1,x1) xor y1) ) xor y2

# This results into
# => E(y1,x1) xor y1 = E(y1,x1) xor y1 xor y2

# x1, y1 can be anything
# y2 = 0^n, since any string of bits xor 0 is itself. 
# x2 = D(y2, E(y1,x1) xor y1)

def main():
	x1 = "12345678123456781234567812345678".decode('hex') # arbitrary 128bit string
	y1 = "90abcdef90abcdef90abcdef90abcdef".decode('hex') # arbitrary 128bit string
	y2 = "00000000000000000000000000000000".decode('hex') # 0^n string

	print "x1:",x1.encode('hex')
	print "y1:",y1.encode('hex')
	print "y2:",y2.encode('hex')

	m1 = f1(x1, y1)
	print "\nf1(x1,y1) = ",m1.encode('hex')
	
	x2 = find_x2(m1, y2)
	print "\nD(y2, f1(x1,y1)) => x2:",x2.encode('hex')

	m2 = f1(x2, y2)
	print "\n\ncheck: f1(x2,y2) =",m2.encode('hex'),"\n==",m1.encode('hex'),"? ",m1==m2

	print "\n"

	# Output:
	# x1: 12345678123456781234567812345678
	# y1: 90abcdef90abcdef90abcdef90abcdef
	# y2: 00000000000000000000000000000000

	# f1(x1,y1) =  115065c6363f7d143c4dfee65894bf7d

	# D(y2, f1(x1,y1)) => x2: 8b701b44711cc43b4f756d7977d7315c

	# check: f1(x2,y2) = 115065c6363f7d143c4dfee65894bf7d 
	# == 115065c6363f7d143c4dfee65894bf7d ?  True


def f1(x, y):
	return strxor(AES.new(y,AES.MODE_ECB).encrypt(x), y)

def find_x2(m, y):
	return AES.new(y,AES.MODE_ECB).decrypt(m)



# xor two strings of different lengths
def strxor(a, b):     
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


main()