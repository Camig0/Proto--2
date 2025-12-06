"""ENCODER :))"""
from blake3 import blake3
from helper import BYTES_PAYLOAD, _ELEMENTS, FACT
from helper import unrank_permutation, rank_permutation
import os

# ============================================================================
# APPROACH 1: Fixed 28-byte encoding (no length preservation)
# ============================================================================
# Use this when you ALWAYS have exactly 28 bytes of data
# Leading zeros are NOT preserved after decoding

def byte_to_perm_fixed(plainBytes: bytes, context: bytes = b"") -> list:
    """
    Fixed-size encoding: Input must be exactly 28 bytes.
    No length preservation - use for CTR mode blocks.
    """
    if len(plainBytes) != BYTES_PAYLOAD:
        raise ValueError(f"Input must be exactly {BYTES_PAYLOAD} bytes")
    
    plaintext_int = int.from_bytes(plainBytes, "big")
    
    # Generate keystream
    hasher = blake3()
    hasher.update(b"keystream_xor_v1")
    hasher.update(context)
    keystream_bytes = hasher.digest(length=BYTES_PAYLOAD)
    keystream_int = int.from_bytes(keystream_bytes, "big")
    
    # XOR and map to permutation
    xored_int = plaintext_int ^ keystream_int
    perm_rank = xored_int % FACT
    
    return unrank_permutation(perm_rank, _ELEMENTS)


def perm_to_byte_fixed(perm: list|str, context: bytes = b"") -> bytes:
    """
    Fixed-size decoding: Always returns exactly 28 bytes.
    """
    if isinstance(perm, str):
        perm_list = list(perm)
    else:
        perm_list = perm
    
    perm_rank = rank_permutation(perm_list, _ELEMENTS)
    xored_int = perm_rank
    
    # Regenerate keystream
    hasher = blake3()
    hasher.update(b"keystream_xor_v1")
    hasher.update(context)
    keystream_bytes = hasher.digest(length=BYTES_PAYLOAD)
    keystream_int = int.from_bytes(keystream_bytes, "big")
    
    # Reverse XOR
    plaintext_int = xored_int ^ keystream_int
    
    # Always return exactly 28 bytes
    return plaintext_int.to_bytes(BYTES_PAYLOAD, "big")


# ============================================================================
# APPROACH 2: Variable-size encoding with length byte (up to 27 bytes data)
# ============================================================================
# Use this when you have variable-length data ≤27 bytes
# Preserves leading zeros and original length

def byte_to_perm_padded(plainBytes: bytes, context: bytes = b"") -> list:
    """
    Variable-size encoding: Input can be 0-27 bytes.
    Length is preserved in first byte.
    """
    if len(plainBytes) > BYTES_PAYLOAD - 1:
        raise ValueError(f"Input too long: max {BYTES_PAYLOAD - 1} bytes")
    
    # Encode length in first byte
    original_len = len(plainBytes)
    
    # Pack: [length_byte][data...][padding...]
    padded = bytes([original_len]) + plainBytes + b"\x00" * (BYTES_PAYLOAD - 1 - len(plainBytes))
    print(bytes([original_len]),plainBytes, b"\x00" * (BYTES_PAYLOAD - 1 - len(plainBytes)))
    print(padded)
    plaintext_int = int.from_bytes(padded, "big")
    
    # Generate keystream
    hasher = blake3()
    hasher.update(b"keystream_xor_v1")  # Different domain separator
    hasher.update(context)
    keystream_bytes = hasher.digest(length=BYTES_PAYLOAD)
    keystream_int = int.from_bytes(keystream_bytes, "big")
    
    # XOR and map to permutation
    xored_int = plaintext_int ^ keystream_int
    perm_rank = xored_int % FACT
    
    return unrank_permutation(perm_rank, _ELEMENTS)


def perm_to_byte_padded(perm: list, context: bytes = b"") -> bytes:
    """
    Variable-size decoding: Returns original length data.
    Preserves leading zeros.
    """
    if isinstance(perm, str):
        perm_list = list(perm)
    else:
        perm_list = perm
    
    perm_rank = rank_permutation(perm_list, _ELEMENTS)
    xored_int = perm_rank
    
    # Regenerate keystream
    hasher = blake3()
    hasher.update(b"keystream_xor_v1")  # Match encoding domain
    hasher.update(context)
    keystream_bytes = hasher.digest(length=BYTES_PAYLOAD)
    keystream_int = int.from_bytes(keystream_bytes, "big")
    
    # Reverse XOR
    plaintext_int = xored_int ^ keystream_int
    plaintext_with_len = plaintext_int.to_bytes(BYTES_PAYLOAD, "big")
    
    # Extract length and return exact data
    original_len = plaintext_with_len[0]
    if original_len > BYTES_PAYLOAD - 1:
        raise ValueError(f"Invalid length byte: {original_len}")
    
    return plaintext_with_len[1:1 + original_len]



# ============================================================================
# USAGE EXAMPLES
# ============================================================================
from blake3 import blake3
from typing import List

def key_sbox_blake3(key: bytes,context:bytes = b"") -> List[int]:
    """Deterministic bijective S-box (0..255) derived from key + nonce using Fisher–Yates."""
    sbox = list(range(256))
    # We'll run Fisher-Yates from high->low using BLAKE3 bytes as randomness.
    h = blake3(key=key)
    for i in range(255, -1, -1):
        hctx = h.copy()
        hctx.update(context + bytes([i]))  # domain separation + index
        rnd = int.from_bytes(hctx.digest(4), 'little')  # 32-bit randomness per step
        j = rnd % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox

def invert_sbox(sbox: List[int]) -> List[int]:
    inv = [0]*256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv

def apply_sbox(data: bytes, sbox: List[int]) -> bytes:
    return bytes(sbox[b] for b in data)

def xor_keystream(msg: bytes, keystream: bytes) -> bytes:
    if len(keystream) < len(msg):
        raise ValueError("keystream must be at least as long as the message")

    return bytes([m ^ k for m, k in zip(msg, keystream)])

def xor_keystream_reverse(cipher: bytes, keystream: bytes) -> bytes:
    if len(keystream) < len(cipher):
        raise ValueError("keystream must be at least as long as the ciphertext")

    return bytes([c ^ k for c, k in zip(cipher, keystream)])


if __name__ == "__main__":
    plain = b"AAAAAAA"
    key = os.urandom(32)
    xor_key = os.urandom(len(plain))

    sbox = key_sbox_blake3(key,b"a bit of context")
    ciphered = apply_sbox(plain,sbox)
    ciphered = xor_keystream(ciphered,xor_key)

    sbox_2 = key_sbox_blake3(key, b"a bit of context")
    recovered = xor_keystream_reverse(ciphered, xor_key)
    inverted = invert_sbox(sbox_2)
    recovered = apply_sbox(recovered,inverted)

    print(ciphered)
    print(recovered)    