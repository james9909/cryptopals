import base64
import string

# Problem 1
def convert_hex_to_base64(s):
    """Converts hex to base64"""
    return base64.b64encode(s.decode("hex"))

assert convert_hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

# ==============================================================================
# Problem 2

def fixed_xor(s1, s2):
    """XOR's two equal-length, hex-encoded strings"""
    assert len(s1) == len(s2)
    s1 = s1.decode("hex")
    s2 = s2.decode("hex")
    return "".join([chr(ord(x) ^ ord(y)) for x, y in zip(s1, s2)]).encode("hex")

assert fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"

# ==============================================================================
# Problem 3

def single_byte_xor(s, key):
    """XOR's a hex-encoded string against a single character"""
    s = s.decode("hex")
    return "".join([chr(ord(x) ^ ord(key)) for x in s])

# http://www.stealthcopter.com/blog/2010/01/python-cryptography-decoding-a-caesar-shift-frequency-analysis/
frequencies = {"a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253, "e": 0.12702,
               "f": 0.02228, "g": 0.02015, "h": 0.06094, "i": 0.06966, "j": 0.00153,
               "k": 0.00772, "l": 0.04025, "m": 0.02406, "n": 0.06749, "o": 0.07507,
               "p": 0.01929, "q": 0.00095, "r": 0.05987, "s": 0.06327, "t": 0.09056,
               "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150, "y": 0.01974,
               "z": 0.00074, " ": 0.19181}

def calculate_score(s):
    """Gives a score to a string using frequency analysis"""
    return sum([frequencies.get(c.lower(), 0) for c in s])

def decode_single_byte_xor(s):
    """Decodes an xor-encoded string using frequency analysis"""
    dec = ""
    max_score = 0
    key = 0

    for char in range(256):
        candidate = single_byte_xor(s, chr(char))
        score = calculate_score(candidate)
        if score > max_score:
            dec, max_score, key = candidate, score, char

    return dec, key


enc = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
assert decode_single_byte_xor(enc) == ("Cooking MC's like a pound of bacon", 88)

# ==============================================================================
# Problem 4


def detect_single_byte_xor(filename):
    """Detect single byte xor from a file"""
    f = open(filename, "r").read().split("\n")
    dec = ""
    max_score = 0
    key = 0
    for line in f:
        candidate, k = decode_single_byte_xor(line)
        score = calculate_score(candidate)
        if score > max_score:
            dec, max_score, key = candidate, score, k

    return dec, k

assert detect_single_byte_xor("files/4.txt") == ("Now that the party is jumping\n", 64)
