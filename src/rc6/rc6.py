# RC6 works on a single 16 byte block at a time
import common.constants as const

'''global paremeters'''
ROUNDS = const.ROUNDS_DEFAULT  # number of rounds


# force every operation into 32 bit math (mod 2^32)
def u32(x: int) -> int:
    return x & const.WORD_MASK

#circular rotation of a 32 bit word
def rotl32(x, s):
    s = s & 31
    x = x & const.WORD_MASK
    return (x << s) | (x >> (32 - s))  & const.WORD_MASK

def main():
    # --- Test suit --- #
    print("RC6 module test suit")
    # 1.
    print("test u32:")
    print(u32(0x123456789))
    print("\n")
    # 2.
    print("test rotl32:")
    print(u32(rotl32(0x12345678, 4)))  # Example usage
    print("\n")

    # 3.
    print("pack and unpack")
    print("x = pack_block_little_endian(0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0)")
    x = pack_block_little_endian(0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0)  # Example usage
    print("unpacked:", unpack_block_little_endian(x))
    print("\n")

    # --- End of Test suit --- #

# Unpack a 16 byte block into four little endian 32 bit words
# Returns a tuple of four integers
def unpack_block_little_endian(block16: bytes) -> tuple[int,int,int,int]:
    if len(block16) != 16:
        raise ValueError("Block must be exactly 16 bytes")
    
    w0 = int.from_bytes(block16[0:4], 'little')
    w1 = int.from_bytes(block16[4:8], 'little')
    w2 = int.from_bytes(block16[8:12], 'little')
    w3 = int.from_bytes(block16[12:16], 'little')
    return (w0, w1, w2, w3)


# pack four little endian 32 bit words into a 16 byte block
# returns a bytes object of length 16
def pack_block_little_endian(A: int, B: int, C: int, D: int) -> bytes:
    return (A.to_bytes(4, 'little') +
            B.to_bytes(4, 'little') +
            C.to_bytes(4, 'little') +
            D.to_bytes(4, 'little'))

# convert bytes to a list of little endian 32 bit words
# NOTE: ENDING MUST BE "LITTLE"
def bytes_to_words_little_endian(data: bytes) -> list[int]:
    #if key length is not multiple of 4, pad with zeroes to next multiple of 4
    if len(data) % 4 != 0:
        padding_length = 4 - (len(data) % 4) # determine how many bytes to pad
        data += b'\x00' * padding_length

    words = []
    for i in range(0, len(data), 4):
        word = int.from_bytes(data[i:i+4], 'little')
        words.append(word)
    return words


"""RC6 key expansion
user_key: bytes - the key to expand
round: int - number of rounds
returns (or how we want to represent): list[int] - the expanded key as a list of 32 bit words"""
def expand_key(user_key: bytes, rounds: int = const.ROUNDS_DEFAULT) -> list[int]:
    #basic parameters
    w = 32  # word size in bits (4 bytes which equals 32 bits)
    r = round # predefined number of rounds (defined globally)
    b = len(user_key)  # length of user key in bytes
    c = b // 4  # number of words in user key
    if b % 4 != 0:
        c += 1  # account for partial word

    # constants for key schedule
    P32 = const.P32 # euler's constant
    Q32 = const.Q32 # golden ratio

    # produces L[0..c-1] where each entry is a 32 bit word
    L = bytes_to_words_little_endian(user_key)

    # Initialize S array for expanded key
    t = 2 * r + 4  # determine how big S array needs to be
    S = [0] * t #init S array full of zeroes
    #fill S array with arithmetic progression
    S[0] = P32 #first word is P32
    for i in range(1, t):
        S[i] = u32(S[i - 1] + Q32) # with u32 truncation

    # key mixing (stirring array L into S)
    A = B = i = j = 0 # set all to zero
    v = max(c, t)
    for s in range(3 * v):
        A = S[i] = rotl32(u32(S[i] + A + B), 3)
        B = L[j] = rotl32(u32(L[j] + A + B), u32(A + B))
        i = (i + 1) % t
        j = (j + 1) % c

    return S

# RC6 encryption of a single 16 byte block
# steps: unpack, pre whitening, rounds, post whitening, pack back
def encrypt_block(block16: bytes, S: list[int], rounds: int = const.ROUNDS_DEFAULT) -> bytes:
    #unpack block into four 32 bit words
    A, B, C, D = unpack_block_little_endian(block16)
    #pre whitening
    # use of only b,d as per RC6 design
    #whitening B and D first makes the very first t and u depend on the key immediately
    B = u32(B + S[0])
    D = u32(D + S[1])

    #main rounds
    for i in range(1, rounds + 1):
        t = rotl32(u32(B * (2 * B + 1)), 5)
        u = rotl32(u32(D * (2 * D + 1)), 5)
        A = u32(rotl32(u32(A ^ t), u) + S[2 * i])
        C = u32(rotl32(u32(C ^ u), t) + S[2 * i + 1])
        #rotate words
        A, B, C, D = B, C, D, A

    #post-whitening
    A = u32(A + S[2 * rounds + 2])
    C = u32(C + S[2 * rounds + 3])

    #return packed block
    return pack_block_little_endian(A, B, C, D)

def decrypt_block(block16: bytes, S: list[int], rounds: int = const.ROUNDS_DEFAULT) -> bytes:
    #unpack block into four 32 bit words
    A, B, C, D = unpack_block_little_endian(block16)
    #post whitening
    C = u32(C - S[2 * rounds + 3])
    A = u32(A - S[2 * rounds + 2])

    #main rounds (reverse order, literally)
    for i in range(rounds, 0, -1):
        A, B, C, D = D, A, B, C
        t = rotl32(u32(B * (2 * B + 1)), 5)
        u = rotl32(u32(D * (2 * D + 1)), 5)
        C = u32(rotl32(u32(C - S[2 * i + 1]), t) ^ u)
        A = u32(rotl32(u32(A - S[2 * i]), u) ^ t)

    # undo pre whitening
    B = u32(B - S[0])
    D = u32(D - S[1])

    #return packed block
    return pack_block_little_endian(A, B, C, D)

if __name__ == "__main__":
    main()