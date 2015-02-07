# Question 8
# In this question and the next, you are asked to find collisions on two compression functions:
# f1(x,y)=AES(y,x) xor y,  and
# f2(x,y)=AES(x,x) xor y,
# where AES(x,y) is the AES-128 encryption of y under key x. 

# We provide an AES function for you to play with. The function takes as input a key k and an x value and outputs AES(k,x) once you press the "encrypt" button. 
# It takes as input a key k and a y value and outputs AES-1(k,y) once you press the "decrypt" button. All three values k,x,y are assumed to be hex values (i.e. using only characters 0-9 and a-f) and the function zero-pads them as needed. 

# Your goal is to find four distinct pairs (x1,y1),  (x2,y2),  (x3,y3),  (x4,y4) such that f1(x1,y1)=f1(x2,y2) and f2(x3,y3)=f2(x4,y4). 
# In other words, the first two pairs are a collision for f1 and the last two pairs are a collision for f2. 



import sys
from Crypto.Cipher import AES


# Please find (x3,y3), (x4,y4) such that f2(x3,y3)=f2(x4,y4).
# => AES(x3,x3) xor y3 = AES(x4,x4) xor y4
# Since the 'y' is independant of the Encryption, you can choose any y that E(x,x) = y
# => E(x3,x3) xor E(x3,x3) = E(x4,x4) xor E(x4,x4)

# Since any value xor itself = 0
# => 0 = 0



def main():
	x3 = "12345678123456781234567812345678".decode('hex') # arbitrary 128bit string
	x4 = "90abcdef90abcdef90abcdef90abcdef".decode('hex') # arbitrary 128bit string
	
	print "x3:",x3.encode('hex')
	print "x4:",x4.encode('hex')
	

	y3 = find_y(x3)
	print "\nE(x3,x3) = y3 = ",y3.encode('hex')

	y4 = find_y(x4)
	print "\nE(x4,x4) = y4 = ",y4.encode('hex')
	
	
	m3 = f2(x3, y3)
	print "\n\ncheck: f2(x3,y3) =",m3.encode('hex')
	m4 = f2(x4, y4)
	print "\ncheck: f2(x4,y4) =",m4.encode('hex')
	print "\nm3 == m4 ? ",m3==m4

	print "\n"

	# Output:
	# x3: 12345678123456781234567812345678
	# x4: 90abcdef90abcdef90abcdef90abcdef

	# E(x3,x3) = y3 =  d7eeee18c420faf0dc7db5ca73a2b817

	# E(x4,x4) = y4 =  ac6f20842f239c423ff5e89c870cca75

	# check: f2(x3,y3) = 00000000000000000000000000000000

	# check: f2(x4,y4) = 00000000000000000000000000000000

	# m3 == m4 ?  True


def f2(x, y):
	return strxor(AES.new(x,AES.MODE_ECB).encrypt(x), y)

def find_y(x):
	return AES.new(x,AES.MODE_ECB).encrypt(x)



# xor two strings of different lengths
def strxor(a, b):     
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


main()