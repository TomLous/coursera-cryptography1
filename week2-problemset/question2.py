# Stanford University
# Cryptography I
# https://www.coursera.org/course/crypto

# Week 2
# Question 2
# Suppose that using commodity hardware it is possible to build a computer for about $200 that can brute force about 1 billion AES keys per second. Suppose an organization wants to run an exhaustive search for a single 128-bit AES key and was willing to spend 4 trillion dollars to buy these machines (this is more than the annual US federal budget). How long would it take the organization to brute force this single 128-bit AES key with these machines? Ignore additional costs such as power and maintenance.


import sys
import numpy


def main():
	computerPrice = 200 # = $200 
	budget = 4*pow(10,12) # =$ 4 trillion dollars

	keysPerSecondPerComputer = pow(10,9) # 1 billion AES keys per second.
	maxNumberKeys = pow(2,128) # 128-bit AES key

	numComputers = budget / computerPrice
	keysPerSecond = keysPerSecondPerComputer * numComputers

	numberOfSeconds = maxNumberKeys / keysPerSecond 

	print numberOfSeconds , "seconds"
	print (numberOfSeconds/3600) , "hours"
	print (numberOfSeconds/3600/24) , "hours"
	print (numberOfSeconds/3600/24/365) , "years"

	hour = 60*60
	day = hour * 24
	week  = day * 7
	month  = day * 31
	year =  day * 365

	print "\n\nMore than an hour but less than a day? ", numberOfSeconds > hour and numberOfSeconds < day
	print "More than a day but less than a week? ", numberOfSeconds > day and numberOfSeconds < week
	print "More than a week but less than a month? ", numberOfSeconds > week and numberOfSeconds < month
	print "More than a 100 years but less than a million years? ", numberOfSeconds > 100*year and numberOfSeconds < pow(10,6)*year
	print "More than a billion (10^9) years? ", numberOfSeconds > pow(10,9)*year

	# 17014118346046923173 seconds
	# 4726143985013034 hours
	# 196922666042209 hours
	# 539514153540 years


	# More than an hour but less than a day?  False
	# More than a day but less than a week?  False
	# More than a week but less than a month?  False
	# More than a 100 years but less than a million years?  False
	# More than a billion (10^9) years?  True




main()