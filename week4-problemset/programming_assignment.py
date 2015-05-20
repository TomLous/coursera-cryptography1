# Question 1
# In this project you will experiment with a padding oracle attack against a toy web site hosted at crypto-class.appspot.com. 
# Padding oracle vulnerabilities affect a wide variety of products, including secure tokens. 
# This project will show how they can be exploited. We discussed CBC padding oracle attacks in Lecture 7.6, but if you want to read more about them, please see Vaudenay's paper. 
#
# Now to business. Suppose an attacker wishes to steal secret information from our target web site crypto-class.appspot.com. 
# The attacker suspects that the web site embeds encrypted customer data in URL parameters such as this:
# http://crypto-class.appspot.com/po?er=f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4
# That is, when customer Alice interacts with the site, the site embeds a URL like this in web pages it sends to Alice. 
# The attacker intercepts the URL listed above and guesses that the ciphertext following the "po?er=" is a hex encoded AES CBC encryption 
# with a random IV of some secret data about Alice's session. 
#
# After some experimentation the attacker discovers that the web site is vulnerable to a CBC padding oracle attack. 
# In particular, when a decrypted CBC ciphertext ends in an invalid pad the web server returns a 403 error code (forbidden request). 
# When the CBC padding is valid, but the message is malformed, the web server returns a 404 error code (URL not found). 
#
# Armed with this information your goal is to decrypt the ciphertext listed above. To do so you can send arbitrary HTTP requests to the web site of the form
# http://crypto-class.appspot.com/po?er="your ciphertext here"
# and observe the resulting error code. The padding oracle will let you decrypt the given ciphertext one byte at a time. 
# To decrypt a single byte you will need to send up to 256 HTTP requests to the site. Keep in mind that the first ciphertext block is the random IV. 
# The decrypted message is ASCII encoded. 
#
# To get you started here is a short Python (http://spark-university.s3.amazonaws.com/stanford-crypto/projects/pp4-attack_py.html) script that sends a ciphertext supplied on the command line to the site and prints the resulting error code. 
# You can extend this script (or write one from scratch) to implement the padding oracle attack. Once you decrypt the given ciphertext, please enter the decrypted message in the box below. 

# This project shows that when using encryption you must prevent padding oracle attacks by either using encrypt-then-MAC as in EAX or GCM, 
# or if you must use MAC-then-encrypt then ensure that the site treats padding errors the same way it treats MAC errors.

import sys
import os
import urllib2
from operator import methodcaller



from Crypto.Hash import SHA256


#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
	def __init__(self):
		self.targetURL = 'http://crypto-class.appspot.com/po?er='

	def query(self, q):
		target = self.targetURL + urllib2.quote(q)    # Create query URL
		req = urllib2.Request(target)         # Send HTTP request to server
		try:
			f = urllib2.urlopen(req)          # Wait for response
		except urllib2.HTTPError, e:          
			return e.code == 404

#--------------------------------------------------------------
# Smart Char Guesser
#--------------------------------------------------------------
class CharGuesser(object):
	def __init__(self):
		self.letterFrequencyOrder = ['e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'c', 'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b', 'v', 'k', 'j', 'x', 'q', 'z']
		self.firstLetterFrequencyOrder = ['T', 'A', 'S', 'H', 'W', 'I', 'O', 'B', 'M', 'F', 'C', 'L', 'D', 'P', 'N', 'E', 'G', 'R', 'Y', 'U', 'V', 'J', 'K', 'Q', 'Z', 'X']
		self.otherCharsOrder = [' ','0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', ',', '!', '?', '&']
		self.commonBigramsOrder = ['th', 'en', 'ng', 'he', 'ed', 'of', 'in', 'to', 'al', 'er', 'it', 'de', 'an', 'ou', 'se', 're', 'ea', 'le', 'nd', 'hi', 'sa', 'at', 'is', 'si', 'on', 'or', 'ar', 'nt', 'ti', 've', 'ha', 'as', 'ra', 'es', 'te', 'ld', 'st', 'et', 'ur']
		self.charsUsed = []


	def guessPrecedingChar(self, currentChar=None):
		if(currentChar):
			# Check common bigrams
			for bigram in self.commonBigramsOrder:
				if bigram[1] == currentChar.lower():
					if not self.checkUsed(bigram[0]):
						return self.setUsed(bigram[0])
					if not self.checkUsed(bigram[0].upper()):
						return self.setUsed(bigram[0].upper())

		# Else check chars in order of probability
		for char in self.letterFrequencyOrder:
			if not self.checkUsed(char):
				return self.setUsed(char)

		# Else check uppercase chars in order of probability of first chars
		for char in self.firstLetterFrequencyOrder:
			if not self.checkUsed(char):
				return self.setUsed(char)

		# Else check common chars, puntcuation, numbers, etc
		for char in self.otherCharsOrder:
			if not self.checkUsed(char):
				return self.setUsed(char)
				
		# Else loop all ASCII from 0-255
		for char in map(lambda x: chr(x), range(0,256)):
			if not self.checkUsed(char):
				return self.setUsed(char)	
		
		# When all else fails?
		return None

	def checkUsed(self,char):
		return char in self.charsUsed

	def setUsed(self,char):
		self.charsUsed.append(char)
		return char



def main():
	cryptoText = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb1".decode('hex')
	blockSize = 16 # 128 bit AES
	cryptoBlocks  = splitCount(cryptoText, blockSize) # x 16 byte blocks, where block 0 is the IV
	messageBlocks = splitCount(("00" * blockSize * (len(cryptoBlocks)-1)).decode('hex'),  blockSize) # init message blocks
	## iv = cryptoBlocks.pop(0) # First item is IV in CBC crypto
	lastChar = None



	po = PaddingOracle()

	# m0 corresponds to c0, which has index 1 in cryptoBlocks. IV has index 0 in cryptoBlocks. 
	# We start with the last block
	for blockNum in reversed(range(0,len(cryptoBlocks))):


		# loop all 16 positions, last to first
		for position in reversed(range(0, blockSize)):
			paddingNum = blockSize - position
			# reinit the crypto block per position
			cryptoSourceBlock = cryptoBlocks[blockNum]
			
			# set the positions with padding XOR known char for the positions we already know (eg when padding is 2 => set position 16 to val XOR 02 xor c[16])
			for pl in range(1, paddingNum): 
				plPos = position + pl
				messageValue = messageBlocks[blockNum][plPos]
				cryptoSourceBlock[plPos] ^= messageValue ^ paddingNum

			# init a ASCII char guesser for this position
			charGuesser = CharGuesser()

			counter = 0
			while counter < 10:
				# reinit the crypto block per guess, with padding on correct pos
				cryptoSourceBlock_bak = cryptoSourceBlock
				guess = charGuesser.guessPrecedingChar(lastChar)

				# Safeguard
				if(guess == None):
					print "Nothing found"
					break;

				print guess
				print paddingNum
				print cryptoSourceBlock.encode('hex')

				# XOR the cryptoblock postion with the guess and the paddingnum
				cryptoSourceBlock[position] ^= ord(guess) ^ paddingNum
				cryptoGuess = buildCryptoString(cryptoText, (blockNum * blockSize), cryptoSourceBlock)
				if(po.query(cryptoGuess)):
					print "found char ", guess
					messageBlocks[blockNum][position] = guess
					break;

				counter += 1



			
			# print cryptoSourceBlock[blockSize - position].encode('hex') 
			# cryptoSourceBlock[position] ^= guess ^ position




	
	# po = PaddingOracle()
	# print po.query() 
	# lg = CharGuesser()
	# print lg.guessPrecedingChar('n')
	# print lg.guessPrecedingChar('n')
	# print lg.guessPrecedingChar('n')
	# print lg.guessPrecedingChar()

def splitCount(s, count):
     return [''.join(x) for x in zip(*[list(s[z::count]) for z in range(count)])]

def buildCryptoString(cryptoText, position, newBlock):
	return cryptoText[position]


main()