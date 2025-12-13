"""helper :("""
from blake3 import blake3

from math import log2

import math
from rubik.cube import Cube as rCube
from magiccube import Cube as mCube
from magiccube import BasicSolver
import random

from typing import Union, List

SOLVED_CUBE_STR = "YYYYYYYYYRRRBBBOOOGGGRRRBBBOOOGGGRRRBBBOOOGGGWWWWWWWWW" #rCube
SOLVED_KEY_CUBE = "YYYYYYYYYRRRRRRRRRGGGGGGGGGOOOOOOOOOBBBBBBBBBWWWWWWWWW" #mCube
KEY_CUBE1 =       "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"
KEY_CUBE2 =       "BYWWYOBBBYGWRRGORGRRYYGOYWWOGGYOROWYRBRYBWGOGOBBGWOWBR" #applied 1 move --> R

ELEMENTS = [
    "0","1","2","3","4","5","6","7","8","9",
    "a","b","c","d","e","f","g","h","i","j",
    "k","l","m","n","o","p","q","r","s","t",
    "u","v","w","x","y","z","A","B","C","D",
    "E","F","G","H","I","J","K","L"
]  # length = 48

_ELEMENTS = [
    "0","1","2","3","4","5","6","7","8","9",
    "a","b","c","d","e","f","g","h","i","j",
    "k","l","m","n","o","p","q","r","s","t",
    "u","v","w","x","y","z","A","B","C","D",
    "E","F","G","H","I","J","K","L", "M","N","O","P","Q","R"
] # length = 54


MOVES = ['Li', 'R', 'Ri', 'U', 'Ui', 'D', 'Di',
         'F', 'Fi', 'B', 'Bi', 'M', 'Mi', 'E', 'Ei',
         'S', 'Si', 'X', 'Xi', 'Y', 'Yi', 'Z', 'Zi'] # for rubikcube

_MOVES = ["L'", 'R', "R'", 'U', "U'", 'D', "D'",
         'F', "F'", 'B', "B'", 'M', "M'", 'E', "E'",
         'S', "S'", 'X', "X'", 'Y', "Y'", 'Z', "Z'"] 
# _MOVES = [ "L'", 'R', "R'", 'U', "U'", 'D', "D'",
#          'F', "F'", 'B', "B'", 'M', "M'"] 


# ---- Updated 54-element list ----

N = len(_ELEMENTS)
FACT = math.factorial(N)
BYTES_PAYLOAD = 54

# ---- factorial number system rank/unrank ----
def rank_permutation(perm, elements):
    elems = elements.copy()
    n = len(elems)
    rank = 0
    for i in range(n):
        idx = elems.index(perm[i])
        rank += idx * math.factorial(n - i - 1)
        elems.pop(idx)
    return rank

def unrank_permutation(index, elements):
    elems = elements.copy()
    n = len(elems)
    perm = []
    for i in range(n - 1, -1, -1):
        f = math.factorial(i)
        pos = index // f
        index %= f
        perm.append(elems.pop(pos))
    return perm


# ---- random cube helper ----
def random_cube() -> rCube:
    scramble_moves = " ".join(random.choices(MOVES, k=200))
    a = rCube(SOLVED_CUBE_STR)
    a.sequence(scramble_moves)
    return a

# ---- PRF helper func ----
def PRF(key, context, purpose): #untested
    hasher = blake3.new()
    hasher.update(key)
    hasher.update(context)
    hasher.update(purpose)
    return hasher.digest()


def blake3_combine(length: int = 32, *byte_strings: Union[bytes, List[bytes]]) -> bytes:
    """
    Compute a BLAKE3 hash from N byte strings.
    
    Args:
        length (int): Output length of the hash in bytes.
        *byte_strings: Either multiple byte strings, or a single list/tuple of byte strings.
        
    Returns:
        bytes: BLAKE3 digest of the concatenated input of length `length`.
    """
    # If a single argument is a list/tuple, unpack it
    if len(byte_strings) == 1 and isinstance(byte_strings[0], (list, tuple)):
        byte_strings = byte_strings[0]
    
    h = blake3()
    for b in byte_strings:
        if not isinstance(b, bytes):
            raise TypeError("All inputs must be bytes")
        h.update(b)
    
    return h.digest(length)


# ---- seeded random cube ----
# def seeded_random_cube(seed,length=200)-> mCube: #untested
#     def get_moves(seed,length = 20):
#         for i in range(length):
#             index = seed[i] % len(_MOVES)
#             yield _MOVES[index]
#     moves = " ".join(get_moves(seed,length))
#     cube = mCube(3,SOLVED_KEY_CUBE)
#     cube.rotate(moves)
#     return mCube(3,cube.get())

def seeded_random_cube(seed: bytes, move_count: int = 60) -> mCube:
    """
    Deterministically generate a ** uniformly random ** cube state from a short seed.
    Uses BLAKE3 as a stream cipher with proper rejection sampling.
    60 moves ≈ 2^65 possible states (cryptographic overkill).
    """
    moveset = list(_MOVES)  # e.g., 18 basic moves
    moves = []
    
    # --- Rejection sampling setup ---
    # For uniform distribution, reject values that cause modulo bias
    # 65536 = 2^16, so we use 2-byte samples
    rejection_threshold = 65536 - (65536 % len(moveset))
    
    # --- BLAKE3 as a CSPRNG ---
    # Seekable, infinite output: call digest(seek=offset) for more bytes
    hasher = blake3(seed)
    
    # --- Main loop: generate moves without bias ---
    byte_offset = 0
    while len(moves) < move_count:
        # Generate 64-byte chunk (32 samples) at a time
        # seek=byte_offset ensures we get a continuous stream
        keystream = hasher.digest(length=64, seek=byte_offset)
        byte_offset += 64
        
        # Process 2-byte samples
        for i in range(0, len(keystream), 2):
            if len(moves) == move_count:
                break
            
            # Combine two bytes into a number 0..65535
            sample = int.from_bytes(keystream[i:i+2], 'little')
            
            # Rejection sampling: only accept unbiased samples
            if sample < rejection_threshold:
                move_index = sample % len(moveset)
                moves.append(moveset[move_index])
    
    # --- Apply moves to cube ---
    cube = mCube(3, SOLVED_KEY_CUBE)
    cube.rotate(" ".join(moves))
    return cube

# ---- function to get moves to solve cube x ----
def get_solve_moves(cube:mCube, mode:bool=False)-> str: #untested
    '''
        gets the moves that solve a cube x

        cube must be mCube lol

       mode: bool
      False: mCube move notation\n
       True: rCube move notation

     Return: string of move notation separated by spaces
          '''
    history_length = len(cube.history())
    solver = BasicSolver(cube)
    solver.solve()
    moves = " ".join([str(i) for i in cube.history()][history_length:]) #currently in mCube notation
    #                                                ^^^^^^^^^^^^^^^^^ done so that to avoid previous move history

    if mode:
        moves = moves.replace("'", "i")

    return moves


# ---- Serialize and dserailize functions ----

def serialize(data:str|int|bytes, mode)->bytes: # this should really be a helper func
    """Convert any type to canonical byte string"""
    if mode == "bytes":
        return data  # Already bytes
    
    elif mode == "utf-8":
        return data.encode('utf-8') + b'\x00'  # Add null terminator
    
    elif mode == "int":
        # Convert to big-endian bytes
        return data.to_bytes((data.bit_length() + 7)//8, 'big') + b'\x80'  # Marker
    
    else:
        raise ValueError(f"Unknown mode: {mode}")

def deserialize(data:bytes, mode)-> bytes|str|int: # this should rlly be a helper func
    """Reverse the canonical serialization process."""

    
    if mode == "bytes":
        return data

    elif mode == "utf-8":
        if not data.endswith(b'\x00'):
            raise ValueError("Invalid UTF-8 serialized form (missing null terminator)")
        return data[:-1].decode("utf-8")

    elif mode == "int":
        if not data.endswith(b'\x80'):
            raise ValueError("Invalid int serialized form (missing 0x80 marker)")
        raw = data[:-1]               # remove marker
        if len(raw) == 0:
            return 0                  # special case: int = 0
        return int.from_bytes(raw, "big")

    else:
        raise ValueError(f"Unknown mode: {mode}")

# ---- Plaintext Whittening ----


# ---- Padding/ Unpadding ----
def pad_with_random(plainbytes: bytes, block_size:int = BYTES_PAYLOAD, context:bytes = b"") -> bytes:
    """
    Format: [plaintext][random_padding][length_byte]
    
    Example (block_size=28, plaintext=5 bytes):
    [h][e][l][l][o][R][R][R]...[R][R][R][5]
     ↑  plaintext  ↑  22 random bytes  ↑ len
    """
    
    msg_len = len(plainbytes)
    padding_len = block_size - msg_len  # Reserve 1 byte for length
    
    # Generate deterministic random padding from IV
    hasher = blake3()
    hasher.update(context)
    hasher.update(b"random_padding")
    random_padding = hasher.digest(length=padding_len)
    
    # Build: [message][random_padding][length]
    padded = plainbytes + random_padding + bytes([msg_len])
    
    assert len(padded) == BYTES_PAYLOAD
    return padded

#b"\xe8{\x96'y\x8bX\xfa\xd2\x0b\x7f6\n1j\x1f\x00\x00\x00\x00"
#p len == 2
def unpad_random(padded: bytes, context:bytes = b"") -> bytes:
    """
    Extract original message from randomly padded block
    """
    msg_len = padded[-1]  # Length is last byte
    
    if msg_len >= len(padded):
        raise ValueError(f"Invalid padding length: {msg_len}")
    
    observed_padding = padded[msg_len:-1]
    padding_len = len(padded) - msg_len -1

    hasher = blake3()
    hasher.update(context)
    hasher.update(b"random_padding")
    random_padding = hasher.digest(length=padding_len)

    assert observed_padding == random_padding

    
    
    return padded[:msg_len]


if __name__ == "__main__":
    key = blake3_combine(32,b"ratata", b"amongus")
    print(len(key))
    print(key)
