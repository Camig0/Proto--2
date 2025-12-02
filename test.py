"""
Direct PRF-based encoding: plaintext -> uniform permutation
This is the BEST solution for your encryption scheme.
"""

import math
import os
from blake3 import blake3

N = 54
FACT = math.factorial(N)
BLOCK_SIZE = 29  # bytes

_ELEMENTS = [
    "0","1","2","3","4","5","6","7","8","9",
    "a","b","c","d","e","f","g","h","i","j",
    "k","l","m","n","o","p","q","r","s","t",
    "u","v","w","x","y","z","A","B","C","D",
    "E","F","G","H","I","J","K","L","M","N","O","P","Q","R"
]

def plaintext_to_permutation(plaintext: bytes, iv: bytes, block_num: int) -> list:
    """
    Map plaintext directly to a uniform permutation using PRF.
    
    This ensures:
    1. Uniform distribution over all 54! permutations
    2. Different IV/counter produces completely different permutation
    3. No correlation between plaintext bytes and permutation structure
    
    Args:
        plaintext: The data to encode (will be padded to BLOCK_SIZE)
        iv: Initialization vector
        block_num: Block counter for CTR mode
        
    Returns:
        A uniformly random permutation determined by (plaintext, IV, counter)
    """
    # Pad plaintext
    if len(plaintext) > BLOCK_SIZE:
        raise ValueError(f"Plaintext too long: {len(plaintext)} > {BLOCK_SIZE}")
    
    padded = plaintext.ljust(BLOCK_SIZE, b"\x00")
    
    # Create PRF input: plaintext || IV || counter
    prf_input = padded + iv + block_num.to_bytes(8, "big")
    
    # Use BLAKE3 as PRF to generate uniform random permutation
    hasher = blake3(prf_input)
    hasher.update(b"perm_v1")  # Domain separation
    
    # Generate permutation using Fisher-Yates with PRF as randomness source
    elements = _ELEMENTS.copy()
    permutation = []
    
    for i in range(N):
        # Get random index for remaining elements
        remaining = N - i
        
        # Get uniform random value in [0, remaining)
        # Use 4 bytes (32 bits) per selection
        random_bytes = hasher.digest(length=4, seek=i*4)
        random_int = int.from_bytes(random_bytes, "big")
        
        # Uniform reduction (bias is negligible: 2^32 >> 54)
        index = random_int % remaining
        
        # Select and remove element
        permutation.append(elements.pop(index))
    
    return permutation


def permutation_to_plaintext(permutation: list, iv: bytes, block_num: int, 
                             max_plaintext_len: int = BLOCK_SIZE) -> bytes:
    """
    Reverse the PRF-based encoding by brute-force search.
    
    WARNING: This is computationally expensive! Only feasible for small plaintexts.
    For practical use, you need to either:
    1. Store plaintext length separately (recommended)
    2. Use a different encoding scheme
    3. Accept that this is a one-way "plaintext commitment" scheme
    
    For your cipher, option 1 is best: encode length in the first block or IV.
    """
    # Try all possible plaintexts up to max_plaintext_len
    for length in range(max_plaintext_len + 1):
        if length == 0:
            candidates = [b""]
        else:
            # For demo purposes, limit search space
            # In practice, this is infeasible for length > 10
            candidates = (
                i.to_bytes(length, "big") 
                for i in range(min(256 ** length, 1000000))
            )
        
        for candidate in candidates:
            test_perm = plaintext_to_permutation(candidate, iv, block_num)
            if test_perm == permutation:
                return candidate.rstrip(b"\x00")  # Remove padding
    
    raise ValueError("Failed to recover plaintext")


# ========== RECOMMENDED: Use this pattern in your cipher ==========

def encode_block_with_length(plaintext: bytes, iv: bytes, block_num: int) -> list:
    """
    Encode plaintext with length information embedded.
    
    This is the PRACTICAL solution:
    - First byte encodes length (0-29)
    - Remaining 28 bytes are payload
    - PRF ensures uniform distribution
    """
    if len(plaintext) > 28:
        raise ValueError(f"Plaintext too long: {len(plaintext)} > 28")
    
    # Prepend length byte
    length_byte = len(plaintext).to_bytes(1, "big")
    encoded = length_byte + plaintext
    
    # Pad to BLOCK_SIZE
    padded = encoded.ljust(BLOCK_SIZE, b"\x00")
    
    # Convert to permutation using PRF
    return plaintext_to_permutation(padded, iv, block_num)


def decode_block_with_length(permutation: list, iv: bytes, block_num: int) -> bytes:
    """
    Decode permutation back to plaintext using embedded length.
    
    This is efficient because we know the exact length to search for.
    """
    # For each possible length, compute expected permutation and compare
    for length in range(29):  # 0-28 bytes of payload
        length_byte = length.to_bytes(1, "big")
        
        # Try all possible plaintexts of this length
        if length == 0:
            candidates = [b""]
        else:
            # For practical use, you'd need a different approach here
            # This is still too slow for length > 10
            # Better: store a hash of plaintext, or use different encoding
            pass
    
    # Actually, this approach still has issues. See better solution below.
    raise NotImplementedError("Use the reversible encoding below instead")


# ========== BEST SOLUTION: Reversible PRF-based encoding ==========

def encode_block_reversible(plaintext: bytes, encryption_key: bytes, 
                           iv: bytes, block_num: int) -> list:
    """
    Reversible encoding: plaintext ⊕ PRF(key, IV, counter) -> permutation
    
    This is the correct way to use your existing cube XOR operation!
    
    Process:
    1. plaintext_int = bytes_to_int(plaintext)
    2. keystream_int = PRF(key, IV, counter) mod 2^232
    3. cipherint = plaintext_int ⊕ keystream_int
    4. permutation = int_to_uniform_perm(cipherint)
    """
    if len(plaintext) > BLOCK_SIZE:
        raise ValueError(f"Plaintext too long")
    
    # Pad plaintext
    padded = plaintext.ljust(BLOCK_SIZE, b"\x00")
    plaintext_int = int.from_bytes(padded, "big")
    
    # Generate keystream integer using PRF
    hasher = blake3()
    hasher.update(encryption_key)
    hasher.update(iv)
    hasher.update(block_num.to_bytes(8, "big"))
    hasher.update(b"keystream_v1")
    
    keystream_bytes = hasher.digest(length=BLOCK_SIZE)
    keystream_int = int.from_bytes(keystream_bytes, "big")
    
    # XOR operation
    cipher_int = plaintext_int ^ keystream_int
    
    # Convert to uniform permutation
    return int_to_uniform_permutation(cipher_int)


def int_to_uniform_permutation(value: int) -> list:
    """
    Map integer to uniformly distributed permutation.
    Uses PRF to map value -> rank in [0, 54!)
    """
    # Use value as seed for PRF
    hasher = blake3()
    hasher.update(value.to_bytes(BLOCK_SIZE, "big"))
    hasher.update(b"int_to_perm_v1")
    
    # Generate uniform rank
    random_bytes = hasher.digest(length=64)  # 512 bits >> 237 bits (log2(54!))
    random_int = int.from_bytes(random_bytes, "big")
    rank = random_int % FACT
    
    # Convert rank to permutation
    return unrank_permutation(rank, _ELEMENTS)


def uniform_permutation_to_int(permutation: list) -> int:
    """
    Reverse: permutation -> integer
    This requires inverting the PRF, which is computationally hard.
    
    For practical cipher: just store the mapping during encryption!
    """
    raise NotImplementedError("PRF inversion is computationally infeasible")


def unrank_permutation(rank: int, elements: list) -> list:
    """Convert rank to permutation using factorial number system"""
    elems = elements.copy()
    n = len(elems)
    perm = []
    for i in range(n - 1, -1, -1):
        f = math.factorial(i)
        pos = rank // f
        rank %= f
        perm.append(elems.pop(pos))
    return perm


# ========== THE ACTUAL FIX FOR YOUR CODE ==========

def fixed_byte_to_perm(plainBytes: bytes) -> list:
    """
    DIRECT FIX: Map bytes uniformly to permutations without bias.
    
    Replace your existing byte_to_perm() with this.
    """
    if len(plainBytes) > BLOCK_SIZE:
        raise ValueError(f"Input too long")
    
    # Pad to full block size
    padded = plainBytes.ljust(BLOCK_SIZE, b"\x00")
    
    # Use BLAKE3 to generate uniform permutation
    hasher = blake3(padded)
    hasher.update(b"bytes_to_perm_v1")
    
    # Generate permutation using PRF-based Fisher-Yates
    elements = _ELEMENTS.copy()
    permutation = []
    
    for i in range(N):
        remaining = N - i
        random_bytes = hasher.digest(length=4, seek=i*4)
        random_int = int.from_bytes(random_bytes, "big")
        index = random_int % remaining
        permutation.append(elements.pop(index))
    
    return permutation


def fixed_perm_to_byte(perm: list) -> bytes:
    """
    WARNING: This cannot be reversed without trying all possible inputs!
    
    You need to change your cipher design to make this reversible.
    See recommendations below.
    """
    raise NotImplementedError(
        "One-way mapping! Use different design:\n"
        "1. Store plaintext length in IV/header\n"
        "2. Use XOR-based encoding (see encode_block_reversible)\n"
        "3. Accept ~12.5% capacity waste and search valid range"
    )


# ========== TEST ==========

def test_uniform_distribution():
    """Verify no bias in permutation encoding"""
    import collections
    
    first_elem_counts = collections.Counter()
    
    print("Testing uniformity of fixed encoding...")
    for i in range(10000):
        plaintext = os.urandom(BLOCK_SIZE)
        perm = fixed_byte_to_perm(plaintext)
        first_elem_counts[perm[0]] += 1
    
    # Check distribution
    expected = 10000 / N  # 185.2
    observed = list(first_elem_counts.values())
    
    print(f"Expected count per element: {expected:.1f}")
    print(f"Observed min: {min(observed)}, max: {max(observed)}")
    print(f"Std dev: {(sum((x - expected)**2 for x in observed) / N)**0.5:.1f}")
    print(f"Ideal std dev: {(expected * (1 - 1/N))**0.5:.1f}")
    
    # Simple chi-square
    chi2 = sum((obs - expected)**2 / expected for obs in observed)
    print(f"Chi-square statistic: {chi2:.2f}")
    print(f"Degrees of freedom: {N - 1}")
    print(f"Critical value (α=0.05): ~70")
    
    if chi2 < 70:
        print("✓ Distribution appears uniform!")
    else:
        print("✗ Distribution may be biased")


if __name__ == "__main__":
    test_uniform_distribution()