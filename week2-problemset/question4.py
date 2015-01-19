# Stanford University
# Cryptography I
# https://www.coursera.org/course/crypto

# Week 2
# Question 4
# Recall that the Luby-Rackoff theorem discussed in Lecture 3.2 states that applying a three round Feistel network to a secure PRF gives a secure block cipher. 
# Let's see what goes wrong if we only use a two round Feistel. Let F:Kx{0,1}32->{0,1}32 be a secure PRF. Recall that a 2-round Feistel defines the following PRP   
# F2:K2x{0,1}64->{0,1}64: 
# Two round Feistel
# Here R0 is the right 32 bits of the 64-bit input and L0 is the left 32 bits. 

# One of the following lines is the output of this PRP F2 using a random key, while the other three are the output of a truly random permutation f:{0,1}64->{0,1}64. All 64-bit outputs are encoded as 16 hex characters. Can you say which is the output of the PRP?   Note that since you are able to distinguish the output of F2 from random, F2 is not a secure block cipher, which is what we wanted to show. 

# Hint: First argue that there is a detectable pattern in the xor of F2(.,0^64) and F2(.,1^32 0^32). Then try to detect this pattern in the given outputs.

# On input 0^64 the output is "290b6e3a 39155d6f".    On input 1^32 0^32 the output is "d6f491c5 b645c008".
# On input 0^64 the output is "4af53267 1351e2e1".    On input 1^32 0^32 the output is "87a40cfa 8dd39154".
# On input 0^64 the output is "5f67abaf 5210722b".    On input 1^32 0^32 the output is "bbe033c0 0bc9330e".
# On input 0^64 the output is "2d1cfa42 c0b1d266".    On input 1^32 0^32 the output is "eea6e3dd b2146dd0".


import sys
import numpy
from operator import methodcaller


def main():
	cyphers = [
	[["290b6e3a","39155d6f"], ["d6f491c5","b645c008"]],
	[["4af53267","1351e2e1"], ["87a40cfa","8dd39154"]],
	[["5f67abaf","5210722b"], ["bbe033c0","0bc9330e"]],
	[["2d1cfa42","c0b1d266"], ["eea6e3dd","b2146dd0"]],

	[["5f67abaf","5210722b"], ["bbe033c0","0bc9330e"]],
	[["4af53267","1351e2e1"], ["87a40cfa","8dd39154"]],	
	[["2d1cfa42","c0b1d266"], ["eea6e3dd","b2146dd0"]],
	[["9f970f4e","932330e4"], ["6068f0b1","b645c008"]],

	]	

	for arow in cyphers:
		print "\n", arow
		for i in range(0,2):
			
			val1 = arow[0][i] #+ arow[0][1]
			val2 = arow[1][i] #+ arow[1][1]
			xor = hexStrToInt(val1) ^ hexStrToInt(val2)
			print " %s xor %s => %s" % (val1, val2, intToHexStr(xor))
		
			# [['290b6e3a', '39155d6f'], ['d6f491c5', 'b645c008']]
			# ==>  290b6e3a xor d6f491c5 => ffffffff
			#  39155d6f xor b645c008 => 8f509d67

			# [['4af53267', '1351e2e1'], ['87a40cfa', '8dd39154']]
			#  4af53267 xor 87a40cfa => cd513e9d
			#  1351e2e1 xor 8dd39154 => 9e8273b5

			# [['5f67abaf', '5210722b'], ['bbe033c0', '0bc9330e']]
			#  5f67abaf xor bbe033c0 => e487986f
			#  5210722b xor 0bc9330e => 59d94125

			# [['2d1cfa42', 'c0b1d266'], ['eea6e3dd', 'b2146dd0']]
			#  2d1cfa42 xor eea6e3dd => c3ba199f
			#  c0b1d266 xor b2146dd0 => 72a5bfb6

def hexStrToInt(s):
	return int(s, 16)

def intToHexStr(i):
	return hex(i)[2:]


main()