"""
CSE 107 Homework 1, Part 2: Break a PRG
When you submit this file, it must be named "hw1_part2.py"
"""
import sys
from os import urandom

def list_collaborators():
	# TODO: Edit the string below to list your collaborators. The autograder won't accept your submission until you do.
	return "no collaborators."

def LFSR107(seed, output_bytelen=107):
	"""
	This PRG is an example of something called an LFSR (short for Linear Feedback Shift Register).
	LFSRs are used as part of many real-world stream ciphers because they're very fast (and cheap) when implemented in hardware.
	This LFSR has a 24 byte internal state, and it outputs one byte every "clock cycle".
	Each clock cycle, the state "shifts up" so that the byte that used to be in state[i] moves to state[i+1]. 
	(This is why it's a "shift register")
	The byte that was in state[23] gets "shifted out" and is the output byte for that clock cycle.
	The byte that gets "shifted in" to be the new state[0] is obtained by xor'ing together specific positions of the state.
	(This is the "linear feedback")

	Note that unlike the PRGs from the in-class activity, here we're working with whole bytes rather than individual bits.
	"""

	if type(seed) != bytes or len(seed) != 16:
		raise TypeError("seed should be a bytestring of length 16")

	# Initialize the state
	state = bytearray(24) # in python, bytearrays are a mutable arrays of bytes, whereas bytestrings are immutable
	state[0:16] = seed # overwrites state from byte 0 (inclusive) to byte 16 (exclusive)
	state[16:24] = [0xC5, 0xE1, 0x07, 0xC5, 0xE1, 0x07, 0xff, 0xff]

	out = bytearray()
	# Now repeatedly "clock" the LFSR. Discard the first 30 bytes of output to be sure the state gets all mixed together before we output anything.
	for i in range(30 + output_bytelen):
		# output the top byte of state
		if i >= 30:
			out.append(state[23])

		# compute a byte that will be the new state[0] by xoring some other state bytes together
		# (remember, in python the ^ operator means (bitwise) xor)
		new_byte = state[0] ^ state[4] ^ state[22] ^ state[23]

		# shift all the bytes toward the top, and set state[0] to the new byte
		state[1:24] = state[:23]
		state[0] = new_byte

	return bytes(out)

"""
Here's where you implement your adversary that distinguishes the output of the above PRG from random!
""" # "sample" is a length-107 bytestring that's either PRG output or truly random
def adversary(sample: bytes) -> int:
    """
    Return 1 if `sample` looks like LFSR107 output, 0 if it looks truly random.
    """
    def check(j):
        return (
            sample[j] ^ sample[j+1] ^ sample[j+19] ^
            sample[j+23] ^ sample[j+24]
        ) == 0

    # make sure we have enough bytes
    if len(sample) < 26:
        return 0

    # require both relations to hold
    return 1 if (check(0) and check(1)) else 0

# ------------------------------------------------------------------------------
# You don't need to (and should not) edit anything below, but feel free to read it if you're curious!
# It's for letting you test your code locally and for interfacing with the autograder

def test_locally():
	print("Measuring the advantage of your PRG adversary...")
	print("  Testing your adversary 5000 times in the real (pseudorandom) world...")
	total = 0
	for i in range(5000):
		if adversary(LFSR107(urandom(16))) == 1: # here sample is the output of LFSR107 on a random 16-byte seed
			total += 1
	pr_real = total/5000
	print(f"    In the \"real world\", your adversary outputs 1 with probability roughly {pr_real}") 
	# The f before the above string makes it a "format string". {pr_real} gets replaced with the value of pr_real

	print("  Testing your adversary 5000 times in the random world...")
	total = 0
	for i in range(5000):
		if adversary(urandom(107)) == 1: # here sample is 107 truly random bytes
			total += 1
	pr_random = total/5000
	print(f"    In the \"random world\", your adversary outputs 1 with probability roughly {pr_random}")

	advantage = pr_real - pr_random
	print(f"  Your advantage in the PRG game is {pr_real} - {pr_random} = {advantage} (up to measurement error)")

	if abs(advantage) >= 0.999:
		print("Hooray! Very well done! You've completely and utterly broken this PRG.")
	elif abs(advantage) >= 0.99:
		print("Nicely done! The autograder should give you basically full credit: all but one point. To get that final point, can you make your advantage .999 or higher?")
	elif abs(advantage) >= 0.4:
		print("Off to a good start! The autograder should give you some partial credit, but try to improve your adversary to have a better advantage")
	else:
		print("This advantage isn't high enough to get credit.")

def interact_with_autograder():
	# Run in 'autograder' mode, where we read in a file with one hex-encoded challenge per line
	# and we write an output file where each line has the corresponding output from the adversary
	with open("part2_challenge", "r") as f_in:
		with open("part2_response", "x") as f_out:
			for line in f_in:
				sample = bytes.fromhex(line.strip())
				if adversary(sample) == 1:
					f_out.write("1\n")
				else:
					f_out.write("0\n")

if __name__ == "__main__":
	# sys.argv is the list of command-line arguments, where sys.argv[0] is the name of this file, sys.argv[1] is the first argument, sys.argv[2] is the second, etc.
	if len(sys.argv) >= 2 and sys.argv[1] == "--autograder":
		interact_with_autograder()
	else:
		test_locally()