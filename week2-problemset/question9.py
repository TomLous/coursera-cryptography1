# Stanford University
# Cryptography I
# https://www.coursera.org/course/crypto

# Week 2
# Question 9
# Let R:={0,1}4 and consider the following PRF F:R5xR->R defined as follows:

# F(k,x):= t=k[0] for i=1 to 4 doif (x[i-1]==1) t=t xor k[i] output t 

# That is, the key is k=(k[0],k[1],k[2],k[3],k[4]) in R5 and the function at, for example, 0101 is defined as F(k,0101)=k[0] xor k[2] xor k[4]. 

# For a random key k unknown to you, you learn that 
# F(k,0110)=0011  and  F(k,0101)=1010  and  F(k,1110)=0110 . 
# What is the value of F(k,1101)?    Note that since you are able to predict the function at a new point, this PRF is insecure.



import sys
import numpy
from operator import methodcaller


def main():
	k5 = [
		'0011', # 0
		'0101', # 1 
		'0000', # 2
		'0000', # 3
		'0000'  # 4
	]

	
	

	xTest = [
		['0110','0011'], # given
		['0101','1010'], # given
		['1110','0110'], # given
		['1101','????']  # target

	]

	print "xors applied"
	for test in xTest:
		fExplained(test[0], test[1])

	print "\n\nxors calculated"
	for test in xTest:
		f(k5, test[0], test[1])

	print "\n\n deduction:"
	print "\n1. F('0110') xor F('0101') xor F('1110') => 0011 xor 1010 xor 0110"
	print "(k[0] xor k[2] xor k[3]) xor (k[0] xor k[2] xor k[4]) xor (k[0] xor k[1] xor k[2] xor k[3]) => 1111"
	print "(k[0] xor k[1] xor k[2] xor k[4]) => 1111"
	

def fExplained(x, out):
	fstr = "k[0]"
	for i in range (1,5):
		if(int(x[i -1]) == 1):
			fstr =  fstr + ' xor k['+str(i)+"]\t"
		else:
			fstr = fstr + "\t\t\t"

	print x + " => " + fstr + " => \t" + out + " == " + str(binStrToInt(out))
	
def f(k, x, test):
	res = binStrToInt(k[0])
	for i in range (1,5):
		if(int(x[i - 1]) == 1):
			res = res ^ binStrToInt(k[i])
		
	print x + " => " + intToBinStr(res) + " => " + test



def binStrToInt(s):
	try:
		return int(s, 2)
	except ValueError:
		return s
	

def intToBinStr(i):
	return bin(i)[2:].zfill(4)


main()