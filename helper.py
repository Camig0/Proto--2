import math
from rubik.cube import Cube 
import random

SOLVED_CUBE_STR = "OOOOOOOOOYYYWWWGGGBBBYYYWWWGGGBBBYYYWWWGGGBBBRRRRRRRRR"

ELEMENTS = [
    "0","1","2","3","4","5","6","7","8","9",
    "a","b","c","d","e","f","g","h","i","j",
    "k","l","m","n","o","p","q","r","s","t",
    "u","v","w","x","y","z","A","B","C","D",
    "E","F","G","H","I","J","K","L"
]  # length = 48

N = len(ELEMENTS)
FACT = math.factorial(N)

# --- Use 25-byte left-padded payload, guaranteed safe since 2^200 < 48! ---
BYTES_PAYLOAD = 25

MOVES = ['Li', 'R', 'Ri', 'U', 'Ui', 'D', 'Di',
         'F', 'Fi', 'B', 'Bi', 'M', 'Mi', 'E', 'Ei',
         'S', 'Si', 'X', 'Xi', 'Y', 'Yi', 'Z', 'Zi']


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
    """Convert exactly 25 bytes into a unique 48-permutation."""
    if len(data) != BYTES_PAYLOAD:
        raise ValueError(f"Input must be exactly {BYTES_PAYLOAD} bytes long")
    num = int.from_bytes(data, "big")
    # With 25 bytes this should always hold: 0 <= num < 48!
    if num >= FACT:
        raise ValueError("Integer out of range for 48! mapping (unexpected)")
    return unrank_permutation(num, ELEMENTS)


def permutation_to_bytes(perm: list):
    """Convert a 48-permutation back into exactly 25 bytes."""
    index = rank_permutation(perm, ELEMENTS)
    return index.to_bytes(BYTES_PAYLOAD, "big")


# ---- string helpers ----
def str_to_perm_with_len(s: str, encoding="utf-8"):
    data = s.encode(encoding)
    if len(data) > BYTES_PAYLOAD:
        raise ValueError(f"Input too long: max {BYTES_PAYLOAD} bytes")
    # Left-pad with zeros to get exactly 25 bytes
    padded = data.rjust(BYTES_PAYLOAD, b"\x00")
    return bytes_to_permutation(padded)


def perm_to_str_with_len(perm: list, encoding="utf-8"):
    padded = permutation_to_bytes(perm)  # exactly 25 bytes
    payload = padded.lstrip(b"\x00")     # remove left padding
    return payload.decode(encoding)


# ---- random cube helper (unchanged) ----
def random_cube() -> Cube:
    scramble_moves = " ".join(random.choices(MOVES, k=200))
    a = Cube(SOLVED_CUBE_STR)
    a.sequence(scramble_moves)
    return a


if __name__ == "__main__":
    perm = str_to_perm_with_len("abcdefghi ")   # <= 25 bytes payload
    print("perm:", perm)                  # list of 48 symbols
    restored = perm_to_str_with_len(perm)
    print("restored:", restored)
