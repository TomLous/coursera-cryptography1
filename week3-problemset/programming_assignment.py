# Question 1
# Suppose a web site hosts large video file F that anyone can download. 
# Browsers who download the file need to make sure the file is authentic before displaying the content to the user. 
# One approach is to have the web site hash the contents of F using a collision resistant hash and then distribute the resulting short hash value h=H(F) to users via some authenticated channel (later on we will use digital signatures for this). 
# Browsers would download the entire file F, check that H(F) is equal to the authentic hash value h and if so, display the video to the user. 

# Unfortunately, this means that the video will only begin playing after the *entire* file F has been downloaded.
# Our goal in this project is to build a file authentication system that lets browsers authenticate and play video chunks as they are downloaded without having to wait for the entire file. 

# Instead of computing a hash of the entire file, the web site breaks the file into 1KB blocks (1024 bytes). It computes the hash of the last block and appends the value to the second to last block. 
# It then computes the hash of this augmented second to last block and appends the resulting hash to the third block from the end. This process continues from the last block to the first as in the following diagram: 
# (https://d396qusza40orc.cloudfront.net/crypto/images/pp3-fig.jpg)[hashing process]
# The final hash value h0 - a hash of the first block with its appended hash - is distributed to users via the authenticated channel as above. 

# Now, a browser downloads the file F one block at a time, where each block includes the appended hash value from the diagram above. 
# When the first block (B0 || h1) is received the browser checks that H(B0 || h1) is equal to h0 and if so it begins playing the first video block. 
# When the second block (B1 || h2) is received the browser checks that H(B1 || h2) is equal to h1 and if so it plays this second block. This process continues until the very last block. 
# This way each block is authenticated and played as it is received and there is no need to wait until the entire file is downloaded. 

# It is not difficult to argue that if the hash function H is collision resistant then an attacker cannot modify any of the video blocks without being detected by the browser. 
# Indeed, since h0=H(B0 || h1) an attacker cannot find a pair (B`0,h`1)!=(B0,h1) such that h0=H(B0 || h1) since this would break collision resistance of H. 
# Therefore after the first hash check the browser is convinced that both B0 and h1 are authentic.
# Exactly the same argument proves that after the second hash check the browser is convinced that both B1 and h2 are authentic, and so on for the remaining blocks. 

# In this project we will be using SHA256 as the hash function. For an implementation of SHA256 use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), or any other. 
# When appending the hash value to each block, please append it as binary data, that is, as 32 unencoded bytes (which is 256 bits). 
# If the file size is not a multiple of 1KB then the very last block will be shorter than 1KB, but all other blocks will be exactly 1KB. 

# Your task is to write code to compute the hash h0 of a given file F and to verify blocks of F as they are received by the client. In the box below please enter the (hex encoded) hash h0 for this video file.  (https://class.coursera.org/crypto-013/lecture/download.mp4?lecture_id=27)

# You can check your code by using it to hash a different file. In particular, the hex encoded h0 for this video (https://class.coursera.org/crypto-013/lecture/download.mp4?lecture_id=28) file is:
# 03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8

import sys
import os

from Crypto.Hash import SHA256

def main():
	block_size = 1024 #bytes
	# Has to save the files, because they are behind coursera login
	file_target = "files/target.mp4"
	hash_target = ""

	file_check = "files/check.mp4"
	hash_check = "03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8"


	h0_check = calculate_hash(file_check, block_size)
	h0_check_hex = h0_check.encode('hex')
	print "calculated h0 for",file_check,":",h0_check_hex," == ",hash_check,"? ",hash_check==h0_check_hex

	h0_target = calculate_hash(file_target, block_size)
	h0_target_hex = h0_target.encode('hex')
	print "calculated h0 for",file_target,":",h0_target_hex

	# Output:
	# Opening file: files/check.mp4  ;  16927313 bytes; 
	# calculated h0 for files/check.mp4 : 03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8  ==  03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8 ?  True
	# Opening file: files/target.mp4  ;  12494779 bytes; 
	# calculated h0 for files/target.mp4 : 5b96aece304a1422224f9a41b228416028f9ba26b0d1058f400200f06a589949



def calculate_hash(file_path, block_size):
	# Get file size in bytes
	file_size = os.path.getsize(file_path)
	# The last block size 
	last_block_size = file_size % block_size

	
	print "Opening file:",file_path, " ; ",file_size,"bytes; "
	fp = open(file_path, 'rb')

	last_hash = ''
	# read the chuncks
	for chunk in read_reversed_chunks(fp, file_size, last_block_size, block_size):
		# SHA-256 obj
		sha256 = SHA256.new()
		sha256.update(chunk)
		if(last_hash):
			sha256.update(last_hash)
		last_hash = sha256.digest()
	fp.close()

	# Return the last hash (h0)
	return last_hash


def read_reversed_chunks(file_object, file_size, last_chuck_size, chunk_size):
	iter = 0
	last_pos = file_size
	while last_pos>0:
		size = chunk_size
		if(iter == 0):
			size = last_chuck_size

		#print "read from",last_pos - size,"to",last_pos
		file_object.seek(last_pos - size)
		data = file_object.read(chunk_size)
		if not data:
			break

		iter = iter + 1
		last_pos -= size
		yield data

main()