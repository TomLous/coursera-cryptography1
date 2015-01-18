# Stanford University
# Cryptography I
# https://www.coursera.org/course/crypto

# Week 1
# Question 1
# Many Time Pad 

# Let us see what goes wrong when a stream cipher key is used more than once. Below are eleven hex-encoded ciphertexts that are the result of encrypting eleven plaintexts with a stream cipher, all with the same stream cipher key. Your goal is to decrypt the last ciphertext, and submit the secret message within it as solution. 
# Hint: XOR the ciphertexts together, and consider what happens when a space is XORed with a character in [a-zA-Z]. 

import sys
from operator import methodcaller
import re

def main():
	cypherTexts = []
	# cyphertext 1 (0)
	cypherTexts.append("315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e")
	# cyphertext 2 (1)
	cypherTexts.append("234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f")
	# cyphertext 3 (2)
	cypherTexts.append("32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb")
	# cyphertext 4 (3)
	cypherTexts.append("32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa")
	# cyphertext 5 (4) 
	cypherTexts.append("3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070")
	# cyphertext 6 (5)
	cypherTexts.append("32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4")
	# cyphertext 7 (6)
	cypherTexts.append("32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce")
	# cyphertext 8 (7)
	cypherTexts.append("315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3")
	# cyphertext 9 (8)
	cypherTexts.append("271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027")
	# cyphertext 10 (9)
	cypherTexts.append("466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83")
	# cyphertext target (10)
	cypherTexts.append("32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904")
	
	
	# convert all to ASCII
	cypherTextsDecoded = map(methodcaller("decode", "hex"), cypherTexts)

	# chose two to XOR

	## This part of the program is interactive.
	## Keep guessing cribs and see how they might match in various XOR-ed cyphertexts (== XOR-ed plaintext) 
	## Finally choose the longest, fully decrypted crib (6) and the target cypher (10)
	# /begin interactive
	crib = "There are two types of cyptography: one that allows the Government to use brute force to break the code, and one that requires the Government to use brute force to break you"
	xorTextNum1 = 6
	xorTextNum2 = 10
	# /end interatcive
	
	xoredText = strxor(cypherTextsDecoded[xorTextNum1], cypherTextsDecoded[xorTextNum2])

	# loop all individual positions of the XOR-ed crypto (plain) text
	textLength = len(xoredText)
	for i in range(textLength):
			# XOR the substring with the crib
    		substrXoredText = xoredText[i:]
    		cribDraggedText = strxor(substrXoredText,crib)

    		# do an estimated guess wether the text is readable, if so print the guess (in place)
    		if(isreadable(cribDraggedText)):
				printCodePos(i, cribDraggedText, textLength, '.')
    		
    
    	print "\n\nGuess key (when the crib starts lining up):"
    	key = strxor(cypherTextsDecoded[xorTextNum1], crib)
    	print "key: %s"%key.encode('hex')

	print "\n\nDecrypt all messages using the key:"
    	for j, cypher in enumerate(cypherTextsDecoded) :
    		print "[%d] %s" % (j, strxor(cypher, key))



	
	
def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def isreadable(str): # check readability (allow only alphanumeric chars and some punctiation)
	return bool(re.search('^[a-zA-Z0-9\., \'\"\-_\:\(\)]+$', str))

def printCodePos(i, code, maxLen, filler): # output the guess in place of the message
	prefix =  filler*i
	ln = len(code)
	postfix = filler*(maxLen-i-ln)
	print("%s%s%s" % (prefix,code,postfix))
    	

main()
	
## Output
# The secret message is: When using a stream cipher, never use the key more than once
# ..................................................................................C


# Guess key (when the crib starts lining up):
# key: 66396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a19f8aa401a9c6d708f80c066c763fef0123148cdd8e802d05ba98777335daefcecd59c433a6b268b60bf4ef03c9a611098bb3e9a3161edc7b804a33522cfd202d2c68c57376edba8c2ca50027c61246ce2a12b0c4502175010c0a1ba4625786d911100797d8a47e98b0204c4ef06c867a950f11ac989dea88fd1dbf16748749ed4c6f45b384c9d96c4

# Decrypt all messages using the key:
# [0] We can factor the number 15 with quantum computers. We can also factor the number 15 with a dog trained to bark three times - Robert Harley
# [1] Euler would probably enjoy that now his theorem becomes a corner stone of crypto - Annonymous on Euler's theorem
# [2] The nice thing about Keeyloq is now we cryptographers can drive a lot of fancy cars - Dan Boneh
# [3] The ciphertext produced by a weak encryption algorithm looks as good as ciphertext produced by a strong encryption algorithm - Philip Zimmermann
# [4] You don't want to buy a set of car keys from a guy who specializes in stealing cars - Marc Rotenberg commenting on Clipper
# [5] There are two types of cryptography - that which will keep secrets safe from your little sister, and that which will keep secrets safe from your government - Bruce Schneier
# [6] There are two types of cyptography: one that allows the Government to use brute force to break the code, and one that requires the Government to use brute force to break you
# [7] We can see the point where the chip is unhappy if a wrong bit is sent and consumes more power from the environment - Adi Shamir
# [8] A (private-key)  encryption scheme states 3 algorithms, namely a procedure for generating keys, a procedure for encrypting, and a procedure for decrypting.?
# [9]  The Concise OxfordDictionary (2006) defines crypto as the art of  writing o r solving codes. 
# [10] The secret message is: When using a stream cipher, never use the key more than once

