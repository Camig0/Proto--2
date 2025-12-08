from magiccube import Cube as mCube
from crypto_engine import CryptoCube
import os
import scipy
from scipy.stats import chisquare
from helper import _ELEMENTS,N
import math
from collections import Counter, defaultdict
from scipy.stats import chisquare, entropy
import numpy as np

from typing import Callable, Any, Dict, List

from pprint import pprint

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from logger import log_to_file

from datetime import datetime

import base64


#FOR AES



# def test_position_uniformity(cipher, num_samples=1000):
#     """
#     Test if each position in the permutation has uniform distribution.
    
#     This is the CORRECT analogue of byte-frequency testing for permutations.
    
#     For a good permutation cipher:
#     - Position 0 should have all 54 symbols equally likely
#     - Position 1 should have all 54 symbols equally likely
#     - ... and so on
    
#     Expected: p-value > 0.01 for each position
#     """
#     print("="*70)
#     print("TEST 1: Position-Level Uniformity")
#     print("="*70)
#     print("Question: Does each position see all 54 symbols uniformly?")
#     print()
    
#     # Count symbol occurrences at each position
#     position_counts = [Counter() for _ in range(N)]
    
#     for i in range(num_samples):
#         print(i)
#         plaintext = os.urandom(54)
#         ciphertext, iv = cipher.encrypt(plaintext)
        
#         # Count symbols at each position
#         for pos, symbol in enumerate(ciphertext):
#             position_counts[pos][symbol] += 1
    
#     # Chi-square test for each position
#     failed_positions = []
#     p_values = []
    
#     for pos in range(N):
#         observed = [position_counts[pos].get(sym, 0) for sym in _ELEMENTS]
#         expected = [num_samples / N] * N
        
#         chi2, p_value = chisquare(observed, expected)
#         p_values.append(p_value)
        
#         if p_value < 0.01:
#             failed_positions.append(pos)
    
#     # Results
#     print(f"Samples tested: {num_samples}")
#     print(f"Positions tested: {N}")
#     print(f"P-value range: [{min(p_values):.10f}, {max(p_values):.10f}]")
#     print(f"Failed positions (p < 0.01): {len(failed_positions)}")
    
#     if len(failed_positions) <= 3:
#         print("✓ PASS: All positions show uniform distribution")
#         return True
#     else:
#         print(f"✗ FAIL: Positions {failed_positions[:5]}... show bias")
#         return False

def test_byte_position_uniformity(cipher:Callable, num_samples=10000, ):
    """
    Test if each byte position has uniform distribution over 0-255.
    
    For a 54-byte ciphertext output, test:
    - Position 0: Are bytes 0-255 equally likely?
    - Position 1: Are bytes 0-255 equally likely?
    - ... for all 54 positions
    
    Expected: p-value > 0.01 for each position
    """
    print("="*70)
    print("TEST: Byte-Level Position Uniformity")
    print("="*70)
    print("Question: Does each position see byte values 0-255 uniformly?")
    print()
    
    NUM_POSITIONS = 54
    NUM_BYTE_VALUES = 256
    
    # Count byte values at each position
    position_counts = [Counter() for _ in range(NUM_POSITIONS)]
    
    for i in range(num_samples):
        # if i % 100 == 0:
        print(f"Sample {i}/{num_samples}")
        
        plaintext = os.urandom(54)  # Random 54 bytes
        ciphertext, iv = cipher(plaintext)
        
        # Ensure ciphertext is bytes, not string
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('latin-1')  # or appropriate encoding
        
        # Count byte values at each position
        for pos in range(NUM_POSITIONS):
            byte_val = ciphertext[pos]  # This is 0-255
            position_counts[pos][byte_val] += 1
    
    # Chi-square test for each position
    failed_positions = []
    p_values = []
    
    for pos in range(NUM_POSITIONS):
        # Observed frequencies for all 256 byte values
        observed = [position_counts[pos].get(val, 0) for val in range(NUM_BYTE_VALUES)]
        
        # Expected: uniform distribution
        expected_freq = num_samples / NUM_BYTE_VALUES
        expected = [expected_freq] * NUM_BYTE_VALUES
        
        chi2, p_value = chisquare(observed, expected)
        p_values.append(p_value)
        
        if p_value < 0.01:
            failed_positions.append(pos)
    
    #RESULT SUMMARY
    result = {"test": "chi-square byte uniformity",
              "algorithm": cipher.__name__,
              "summary":{
              "sample": num_samples,
              "positions tested": NUM_POSITIONS,
              "expected":f"{min(p_values):.10f}, {max(p_values):.10f}",
              "failed position": failed_positions},
              "details": {
                  "position_counts": position_counts,
                  "p values": p_values
              }
              },



    # Results
    print(f"\nSamples tested: {num_samples}")
    print(f"Positions tested: {NUM_POSITIONS}")
    print(f"Byte values per position: {NUM_BYTE_VALUES}")
    print(f"Expected count per byte value: {num_samples / NUM_BYTE_VALUES:.2f}")
    print(f"P-value range: [{min(p_values):.10f}, {max(p_values):.10f}]")
    print(f"Failed positions (p < 0.01): {len(failed_positions)}")
    
    if len(failed_positions) == 0:
        print("✓ PASS: All positions show uniform byte distribution")
        return result
    else:
        print(f"✗ FAIL: Positions {failed_positions[:10]} show bias")
        return result


def shannon_entropy(data: bytes) -> float:
    """Compute byte-level Shannon entropy in bits."""
    if not data:
        return 0.0

    # Frequency of each byte (0–255)
    freq = [0] * 256
    for b in data:
        
        freq[b] += 1

    N = len(data)
    H = 0.0

    for count in freq:
        if count == 0:
            continue
        p = count / N
        H -= p * math.log2(p)

    return H


def entropy_test_cipher(
    cipher: Callable[..., bytes],
    samples: int = 100,
    plaintext_len: int = 64
) -> Dict[str, Any]:
    """
    Run a Shannon entropy test on a cipher.

    Parameters:
        cipher         - a callable returning ciphertext bytes
        cipher_args    - args passed to the cipher via cipher(*cipher_args)
        samples        - number of random plaintext samples
        plaintext_len  - length of random plaintext (in bytes)

    Returns:
        {
            "entropy_values": [...],
            "average_entropy": float,
            "min_entropy": float,
            "max_entropy": float
        }
    """
    
    entropies: List[float] = []
    ciphertexts: List[bytes] = []

    for _ in range(samples):
        if _ % (samples/10) == 0:
            print(f"sample {_}/{samples}")
        pt = os.urandom(plaintext_len)  # random plaintext
        ct,_ = cipher(pt)   # call the cipher
        # print(type(ct))
        ciphertexts.append(base64.b64encode(ct).decode('utf-8'))
        H = shannon_entropy(ct)
        print(f"DEBUG - Entropy: {H}") 
        entropies.append(H)

    return {
        "test name": "enctropy test",
        "algorithm": cipher.__name__,
        "number of samples": samples,
        "plaintext length" : plaintext_len,
        "Summary":{
        "average_entropy": sum(entropies) / len(entropies),
        "min_entropy": min(entropies),
        "max_entropy": max(entropies),},
        "details": {
            "ciphertexts" : ciphertexts,
            "entropies": entropies}
    }

def crptocube_ctr_wrapper(pt):
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    cipher = CryptoCube(KEYS1,mode="bytes")
    ct, _ = cipher.encrypt_ctr(pt)
    if len(pt) == 54:
        ct= ct[:54]
    return ct, None

def crptocube_wrapper(pt):
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    cipher = CryptoCube(KEYS1,mode="bytes", whitten=False)
    ct, _ = cipher.encrypt(pt)
    if len(pt) == 54:
        ct= ct[:54]
    return ct, None


def AES_wrapper(pt):
    key = os.urandom(32)
    aes_cipher = Cipher(algorithms.AES(key),modes.CTR(b"abdsjekrlsmjfvjs"))
    encryptor = aes_cipher.encryptor()
    ciphertext = encryptor.update(pt) + encryptor.finalize()

    

    return ciphertext, None




def main()->None:
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    cipher = CryptoCube(KEYS1,"bytes",whitten=False)
    results = []

    result = entropy_test_cipher(AES_wrapper, 1000)
    # result = test_byte_position_uniformity(crptocube_wrapper, 1000)
    today = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"{today}.json"
    path = f"stat_tests/{file_name}"
    log_to_file(path, result)


    # pprint(entropy_test_cipher(cipher.encrypt,1000,54))
    # pprint(test_byte_position_uniformity(cipher, num_samples= 10000))


if __name__ == "__main__":
    main()


