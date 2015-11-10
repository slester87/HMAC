__author__ = 'Skip'
import sys
import traceback
import os
import array

# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
    (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
    ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | \
    (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))


def hmac(keyFile, messageFile, outputFile):
    try:
        kFile = open(keyFile)

        sha256(messageFile)
    except IOError:
        print("Seems like there's no such file")
    except:
        traceback.print_exc()
    else:
        print("all done")


class FourByteWord:
    s = bytes()

    def __init__(self, byte_array):
        i = 0

        while i < 4:
            s = s + bytes(byte_array[i])




# From wiki:
#   Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 232
#   Note 2: For each round, there is one round constant k[i] and
#           one entry in the message schedule array w[i], 0 ? i ? 63
#   Note 3: The compression function uses 8 working variables, a through h
#   Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
#           and when parsing message block data from bytes to words, for example,
#           the first word of the input message "abc" after padding is 0x61626380

# @param message The seed of the secure hashing algorithm
def sha256(message):
    # Initialize the hash values
    # (first 32 bits of the fractional parts of the
    # square roots of the first 8 primes, 2...19)
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # Initialize array of round constants:
    # ((first 32 bits of the fractional parts of the
    # cube roots of the first 64 primes 2..311):
    roundConstants = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    #   Pre-process the message
    #   append the bit '1' to the message
    #   append k bits '0', where K is the minimum number >= 0 s.t.
    #   len(message) congruent 448 mod 512bits (or 56 mod 64 bytes)
    #   append len(message) in bits, as 64 bit (8 byte) big endian integer
    #   we will do this at the end of the file

    statinfo = os.stat(message)
    print("The length of the messageFile before pre-processing is " + str(statinfo.st_size) + " bytes")
    print("And " + str(statinfo.st_size) + "(mod 64 bytes) = " + str((statinfo.st_size) % 64) + " bytes.")
    # print("Reminder: 64 bytes = 2^6 * 2^3 bits = 2^9 = 512 bits. We want so pad to 448/512 bits, or 56/64 bytes")
    numberOfPaddingBytes = 56 - (statinfo.st_size % 64)
    fh = open(message, 'rb')
    chunk = bytearray(fh.read(64))
    # Process the message in successive 512-bit chunks

    # v = [0b0000] * 4 # 32 bit entries

    while len(chunk) == 64:
        # do sha on chunk
        w = [0b0000] * 64 * 4  # 32 bit entries

        for i in range(0,63):
            # copy chunk into first 16 words w[0..15] of the message schedule array
            # one entry in w is four times as big as one entry in chunk

            w[i] = chunk[i]
            print(w[i])

        i = 64
        while i < 63*4:
            # Need a four byte word class
            print(w[i]) # The following assumes 32 bit = 4 byte words.
            s0 = (ror(w[i - 15 * 4], 7, 32) ^ ror(w[i - 15 * 4], 18, 32) ^ w[i - 15 * 4] >> 3)
            s1 = (ror(w[i - 2 * 4], 17, 32) ^ ror(w[i - 2 * 4], 19, 32) ^ w[i - 2 * 4] >> 10)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1
            i += 4
        # print(w[i])
        chunk = bytearray(fh.read(64))

    print("length of file is " + str(len(chunk)))
    print(" number of padding bits is " + str(numberOfPaddingBytes))
    padding = bytearray(numberOfPaddingBytes)
    padding[0] = 0x80


    # writing out the padded to file for debugging, for now
    # think about edge case where the file is 56 mod 64 as desired but we still need to pad
    # with open(message, 'rb') as old_buffer, open('paddedFile', 'wb') as new_buffer:
    # copy the old file completely
    #    new_buffer.write(old_buffer.read(statinfo.st_size))
    # and pad it as required
    #   new_buffer.write()


def do_hmac():
    if not len(sys.argv) < 3:
        hmac(str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3]))
    if len(sys.argv) <= 2:
        print("Insufficient parameters passed")
        print("Usage: ./hmac keyFile messageFile ouputFile")


do_hmac()
