__author__ = 'Skip'
import sys
import traceback
import os
import struct
import array

# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
    (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
    ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | \
    (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))


def safe_add(x, y):
    # lsw = (x & 0xFFFF) + (y & 0xFFFF)
    # msw = (x >> 16) + (y >> 16) + (lsw >> 16)
    # return ((msw << 16) | (lsw & 0xFFFF)) & 0xFFFFFFFF
    return (x + y) % 0x100000000


def hmac(keyFile, messageFile, outputFile):
    try:
        sha256_hmac(keyFile, messageFile)
        sha256(messageFile)
    except IOError:
        print("Seems like there's no such file")
    except:
        traceback.print_exc()
    else:
        print("all done")


def get_hmac_key(key_file):
    fh = open(key_file, 'rb')
    return bytearray(fh.read(64))


def sha256_hmac(hmac_key_file, message_file):
    hmac_key = get_hmac_key(hmac_key_file)

    message_file_bits = os.stat(message_file).st_size * 8
    fh = open(message_file, 'rb')

    inner_key_block = [0x36] * 64
    outer_key_block = [0x5C] * 64
    for i in range(0, len(hmac_key)):
        inner_key_block[i] ^= hmac_key[i]
        outer_key_block[i] ^= hmac_key[i]

    inner_hash = sha256_impl(lambda: inner_key_block, lambda: fh.read(64), message_file_bits + 512)
    print(str(inner_hash))
    padded_inner_hash = [0x00] * 32;
    for i in range(0, 8):
        inner_hash_bytes = struct.pack('>L', inner_hash[i])
        padded_inner_hash[i*4] = inner_hash_bytes[0]
        padded_inner_hash[i*4+1] = inner_hash_bytes[1]
        padded_inner_hash[i*4+2] = inner_hash_bytes[2]
        padded_inner_hash[i*4+3] = inner_hash_bytes[3]

    outer_hash = sha256_impl(lambda: outer_key_block, lambda: padded_inner_hash, 768)

    print ('hexarray')
    print_hex_array(outer_hash)

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
    statinfo = os.stat(message)
    print("The length of the messageFile before pre-processing is " + str(statinfo.st_size) + " bytes")
    print("And " + str(statinfo.st_size) + "(mod 64 bytes) = " + str((statinfo.st_size) % 64) + " bytes.")

    # print("Reminder: 64 bytes = 2^6 * 2^3 bits = 2^9 = 512 bits. We want so pad to 448/512 bits, or 56/64 bytes")
    numberOfPaddingBytes = 56 - (statinfo.st_size % 64) - 1
    print("The number of 0x00 bytes is " + str(numberOfPaddingBytes))
    fh = open(message, 'rb')

    computed_hash = sha256_impl(lambda: None, lambda: fh.read(64), statinfo.st_size * 8)
    return computed_hash


def sha256_impl(get_first_chunk, get_next_chunk, message_length_bits, final_chunk = None):
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
    round_constants = [
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

    if (get_first_chunk() == None):
        chunk = bytearray(get_next_chunk())
    else:
        chunk = bytearray(get_first_chunk())

    # Process the message in successive 512-bit chunks
    chunk_num = 0

    # v = [0b0000] * 4 # 32 bit entries
    on_last_chunk = False
    has_extra_chunk = False
    while True:

        # padding
        if (len(chunk) < 56 | on_last_chunk):
            on_last_chunk = True
            orig_chunk_len = len(chunk)
            temp_chunk = bytearray(b'\x00' * 64)
            j = 0
            while j < orig_chunk_len:
                temp_chunk[j] = chunk[j]
                j += 1

            temp_chunk[orig_chunk_len] = 0x80
            chunk = temp_chunk
            file_len = struct.pack('>Q', int(message_length_bits))
            j = 56
            while j < 64:
                chunk[j] = file_len[j - 56]
                j += 1

        elif (len(chunk) < 64):
            # TODO Write
            chunk[len(chunk) + 1] = 0x80
            has_extra_chunk = True
            chunk = pad_last_chunk(chunk)

        # do sha on chunk
        # w = [0b0000] * 64 * 4  # 32 bit entries

        w = [0x00000000] * 64

        i = 0
        while i < 16:
            # copy chunk into first 16 words w[0..15] of the message schedule array
            # one entry in w is four times as big as one entry in chunk
            buffer = [0b00000000] * 4
            buffer[0] = chunk[i * 4]
            buffer[1] = chunk[i * 4 + 1]
            buffer[2] = chunk[i * 4 + 2]
            buffer[3] = chunk[i * 4 + 3]
            # ToDo: double check endian-ness
            w[i] = int(struct.unpack('>I', bytes(buffer))[0])
            i += 1
        i = 16

        while i < 64:
            # Need a four byte word class
            # print(w[i]) # The following assumes 32 bit = 4 byte words.
            s0 = (ror((w[i - 15]), 7, 32) ^ ror((w[i - 15]), 18, 32) ^ (w[i - 15] >> 3))
            s1 = (ror(w[i - 2], 17, 32) ^ ror(w[i - 2], 19, 32) ^ (w[i - 2] >> 10))
            w[i] = safe_add(w[i - 16], safe_add(s0, safe_add(w[i - 7], s1)))
            i += 1
        # print(w[i])

        #    Initialize working variables to current hash value:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Compression from main loop:
        i = 0
        while i < 64:
            s1 = ror(e, 6, 32) ^ ror(e, 11, 32) ^ ror(e, 25, 32)
            ch = (e & f) ^ (~e & g)
            temp1 = safe_add(h, safe_add(s1, safe_add(ch, safe_add(round_constants[i], w[i]))))
            s0 = ror(a, 2, 32) ^ ror(a, 13, 32) ^ ror(a, 22, 32)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = safe_add(s0, maj)

            h = g
            g = f
            f = e
            e = safe_add(d, temp1)
            d = c
            c = b
            b = a
            a = safe_add(temp1, temp2)

            i += 1

        # Add the compressed chunk to the current hash value:
        h0 = safe_add(h0, a)
        h1 = safe_add(h1, b)
        h2 = safe_add(h2, c)
        h3 = safe_add(h3, d)
        h4 = safe_add(h4, e)
        h5 = safe_add(h5, f)
        h6 = safe_add(h6, g)
        h7 = safe_add(h7, h)

        # Produce the final hash value (big-endian)

        # Everything above here is SHA
        if (on_last_chunk):
            break

        next_chunk = get_next_chunk()
        if (next_chunk == None and final_chunk != None):
            chunk = bytearray(final_chunk)
            on_last_chunk = True
        else:
            chunk = bytearray(next_chunk)
        chunk_num += 1

    # digest = append h0, h1, ..., h7
    digest = [0x00000000] * 8
    digest[0] = h0
    digest[1] = h1
    digest[2] = h2
    digest[3] = h3
    digest[4] = h4
    digest[5] = h5
    digest[6] = h6
    digest[7] = h7
    return digest


def print_hex_array(array):
    j = 0
    while j < len(array):
        print("{0:x}".format(array[j]))
        j += 1


def do_hmac():
    if not len(sys.argv) < 3:
        hmac(str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3]))
    if len(sys.argv) <= 2:
        print("Insufficient parameters passed")
        print("Usage: ./hmac keyFile messageFile ouputFile")


do_hmac()
