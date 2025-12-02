from blake3 import blake3

import math
from rubik.cube import Cube as rCube
from magiccube import Cube as mCube
from magiccube import BasicSolver
import random

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

_MOVES = [ "L'", 'R', "R'", 'U', "U'", 'D', "D'",
         'F', "F'", 'B', "B'", 'M', "M'"] 


# ---- Updated 54-element list ----

N = len(_ELEMENTS)
FACT = math.factorial(N)
BYTES_PAYLOAD = 30

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

# ---- safe bytes <-> permutation conversion ----
def bytes_to_permutation(data: bytes):
    """Convert exactly 30 bytes into a unique 54-permutation."""
    if len(data) != BYTES_PAYLOAD:
        raise ValueError(f"Input must be exactly {BYTES_PAYLOAD} bytes long")
    num = int.from_bytes(data, "big")
    if num >= FACT:
        raise ValueError("Integer out of range for 54! mapping")
    return unrank_permutation(num, _ELEMENTS)

def permutation_to_bytes(perm: list):
    """Convert a 54-permutation back into exactly 30 bytes."""
    index = rank_permutation(perm, _ELEMENTS)
    return index.to_bytes(BYTES_PAYLOAD, "big")

# ---- string helpers ----
def str_to_perm_with_len(s: str, encoding="utf-8"):
    data = s.encode(encoding)
    if len(data) > BYTES_PAYLOAD:
        raise ValueError(f"Input too long: max {BYTES_PAYLOAD} bytes")
    padded = data.rjust(BYTES_PAYLOAD, b"\x00")
    return bytes_to_permutation(padded)

def perm_to_str_with_len(perm: list, encoding="utf-8"):
    padded = permutation_to_bytes(perm)
    # Strip leading zeros to recover original string
    payload = padded.lstrip(b"\x00")
    return payload.decode(encoding)

# ---- int helpers ----
def int_to_perm(plainInt):
    if not (0 <= plainInt < FACT):
        raise ValueError(f"int {plainInt} must be >=0 and <54!")
    return unrank_permutation(plainInt, _ELEMENTS)

def perm_to_int(perm):
    return rank_permutation(perm, _ELEMENTS)

# ---- byte helpers ----
#TODO: FIX, COMPLETELY DELETE TS 
def byte_to_perm(plainBytes):
    if len(plainBytes) > BYTES_PAYLOAD:
        raise ValueError(f"Input bytes too long: max {BYTES_PAYLOAD}")
    padded = plainBytes.rjust(BYTES_PAYLOAD, b"\x00")
    num = int.from_bytes(padded, "big")
    if num >= FACT:
        raise ValueError("Integer out of range for 54! mapping")
    return unrank_permutation(num, _ELEMENTS)

def perm_to_byte(perm):
    rank = perm_to_int(perm)
    padded = rank.to_bytes(BYTES_PAYLOAD, "big")
    # Return without leading zeros for consistency
    return padded

# old encoding code
(
# # ---- safe bytes <-> permutation conversion ----
# def bytes_to_permutation(data: bytes):
#     """Convert exactly 25 bytes into a unique 48-permutation."""
#     if len(data) != BYTES_PAYLOAD:
#         raise ValueError(f"Input must be exactly {BYTES_PAYLOAD} bytes long")
#     num = int.from_bytes(data, "big")
#     # With 25 bytes this should always hold: 0 <= num < 48!
#     if num >= FACT:
#         raise ValueError("Integer out of range for 48! mapping (unexpected)")
#     return unrank_permutation(num, ELEMENTS)


# def permutation_to_bytes(perm: list):
#     """Convert a 48-permutation back into exactly 25 bytes."""
#     index = rank_permutation(perm, ELEMENTS)
#     return index.to_bytes(BYTES_PAYLOAD, "big")


# # ---- string helpers ----
# def str_to_perm_with_len(s: str, encoding="utf-8"):
#     data = s.encode(encoding)
#     if len(data) > BYTES_PAYLOAD:
#         raise ValueError(f"Input too long: max {BYTES_PAYLOAD} bytes")
#     # Left-pad with zeros to get exactly 25 bytes
#     padded = data.rjust(BYTES_PAYLOAD, b"\x00")
#     return bytes_to_permutation(padded)


# def perm_to_str_with_len(perm: list, encoding="utf-8"):
#     padded = permutation_to_bytes(perm)  # exactly 25 bytes
#     payload = padded.lstrip(b"\x00")     # remove left padding
#     return payload.decode(encoding)

# # ---- int helpers ----
# def int_to_perm(plainInt):
#     if 0 <= plainInt <= FACT:
#         return unrank_permutation(plainInt, ELEMENTS)
#     raise ValueError("int: {plaintInt} must be > 0 and <48! adjust your plain text.")
 
# def perm_to_int(perm):
#     return rank_permutation(perm, ELEMENTS)

# # ---- byte helpers ----
# def byte_to_perm(plainBytes):
#     return int_to_perm(int.from_bytes(plainBytes, "big"))

# def perm_to_byte(perm):
#     rank = perm_to_int(perm)
#     length = (rank.bit_length() + 7) // 8  
#     return rank.to_bytes(length, "big")
)

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

def serialize(data, mode)->bytes: # this should really be a helper func
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

def deserialize(data, mode)-> bytes|str|int: # this should rlly be a helper func
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

if __name__ == "__main__":
    cube = rCube("".join(_ELEMENTS))
    print("Random Cube:")
    print(cube)

    perm = int_to_perm(FACT-1)
    recovered = perm_to_int(perm)
    print(perm)
    print(recovered)
    permbytes = perm_to_byte("ma0tx1ocjGfevgL8JEB9iCAwO4326Iz57yPRuHbQnDlhdKprNskMFq")
    print(permbytes)