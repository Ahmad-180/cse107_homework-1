from Crypto.Cipher import AES as AES_C # use the AES from pycryptodome
from os import urandom # for cryptographically secure random bytes


##### Helper functions #####

def AES(key, m):
	"""
	Calls the AES block cipher on a message block, returning a ciphertext block.
	key and m must be 16-byte-long bytestrings.

	Hint: the bug is not in this function.
	"""
	if type(key) != bytes or len(key) != 16: raise TypeError("key must be a length-16 bytestring")
	if type(m) != bytes or len(m) != 16: raise TypeError("m must be a length-16 bytestring")
	# The PyCryptodome library doesn't expose the block cipher directly, it has a weird interface and wants us to specify a mode of operation
	# Since m is one block long, AES_k(m) is equivalent to encrypting m in ECB mode
	cipher = AES_C.new(key, AES_C.MODE_ECB)
	return cipher.encrypt(m)

def AES_I(key, c):
	"""
	Calls AES^{-1} (block cipher decryption) on a ciphertext block, returning a message block.
	key and c must be 16-byte-long bytestrings.

	Hint: the bug is not in this function.
	"""
	if type(key) != bytes or len(key) != 16: raise TypeError("key must be a length-16 bytestring")
	if type(c) != bytes or len(c) != 16: raise TypeError("c must be a length-16 bytestring")
	cipher = AES_C.new(key, AES_C.MODE_ECB)
	return cipher.decrypt(c)

def xor_bytestrings(a, b):
	""" xor two bytestrings together. The returned bytestring has length min(len(a), len(b)) """
	return bytes([ ai ^ bi for (ai,bi) in zip(a,b) ])


##### The fun part: encrypt and decrypt #####

def encrypt(msg, sk):
	IV = urandom(16) # IV is 16 random bytes
	out = IV
	counter = int.from_bytes(IV, byteorder="big")
	for i in range(0, len(msg), 16): # this is equivalent to "for (i = 0; i < len(msg); i += 16)" in C
		counter += 1
		counter %= 2**128
		counter_block = counter.to_bytes(length=16, byteorder="big")
		out += xor_bytestrings(
			msg[i : i+16],
			AES(counter_block, sk)
		)
	return out

def decrypt(ctxt, sk):
	if len(ctxt) < 16: raise ValueError("ctxt is too short to be a real ciphertext")
	IV = ctxt[:16]
	counter = int.from_bytes(IV, byteorder="big")
	out = b"" # the b in front of the quotes makes it a bytestring instead of a regular (unicode) string
	for i in range(16, len(ctxt), 16): # this is equivalent to "for (i = 16; i < len(ctxt); i += 16)" in C
		counter += 1
		counter %= 2**128
		counter_block = counter.to_bytes(length=16, byteorder="big")
		out += xor_bytestrings(
			ctxt[i : i+16],
			AES(counter_block, sk)
		)
	return out

# verify that everything seems to work
test_sk = urandom(16)
test_msg = b"this is a multi-block test message to see if decryption works properly"
assert decrypt(encrypt(test_msg, test_sk), test_sk) == test_msg

# alright, tests pass, I guess there are no bugs!