# Stanford University
# Cryptography I
# https://www.coursera.org/course/crypto

# Week 2
# Question 1
# Consider the following five events:
# Correctly guessing a random 128-bit AES key on the first try.
# Winning a lottery with 1 million contestants (the probability is 1/106 ).
# Winning a lottery with 1 million contestants 5 times in a row (the probability is (1/106)5 ).
# Winning a lottery with 1 million contestants 6 times in a row.
# Winning a lottery with 1 million contestants 7 times in a row.
# What is the order of these events from most likely to least likely?


import sys
import numpy


def main():
	amounts = numpy.array([
		pow(2,128), 		# Correctly guessing a random 128-bit AES key on the first try.
		pow(10,6), 		# Winning a lottery with 1 million contestants (the probability is 1/10^6 ).
		pow(pow(10,6),5),		# Winning a lottery with 1 million contestants 5 times in a row (the probability is (1/106)5 ).
		pow(pow(10,6),6),		# Winning a lottery with 1 million contestants 6 times in a row.
		pow(pow(10,6),7),		# Winning a lottery with 1 million contestants 7 times in a row.
	])

	sortIndex = numpy.argsort(amounts)
		
	sortIndex = [x+1 for x in sortIndex]

	print sortIndex
	# result [2, 3, 4, 1, 5]



main()