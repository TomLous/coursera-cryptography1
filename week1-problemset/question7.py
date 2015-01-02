import sys

def main():
	text1 = "attack at dawn"
	encoded1 = "6c73d5240a948c86981bc294814d".decode("hex")
	key = xor_strings(text1, encoded1)

	text2 = "attack at dusk"
	encoded2 = xor_strings(text2, key)
	print encoded2.encode("hex")

def xor_strings(strA, strB):
	return "".join(chr(ord(chrA) ^ ord(chrB)) for (chrA, chrB) in zip(strA, strB))

main()