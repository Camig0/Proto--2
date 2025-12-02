from magiccube import Cube as mCube
from crypto_engine import CryptoCube
import os
import scipy
from scipy.stats import chisquare
from helper import permutation_to_bytes, perm_to_int,_ELEMENTS,N
import math
from collections import Counter, defaultdict
from scipy.stats import chisquare, entropy
import numpy as np

def generate_nist_test_data(keys, filename="ciphertext_bits.txt", size_mb=10):
    """Generate ciphertext for NIST tests (needs ~10MB)"""
    
    cipher = CryptoCube(keys, mode="bytes")
    
    with open(filename, "w") as f:
        bytes_written = 0
        target_bytes = size_mb * 1024 * 1024
        
        while bytes_written < target_bytes:
            plaintext = os.urandom(29)
            ciphertext, iv = cipher.encrypt_ctr(plaintext)
            
            # Convert to binary string
            for block in ciphertext:
                bits = ''.join(format(ord(c), '08b') for c in block)
                f.write(bits)
                bytes_written += len(block)
    
    print(f"Generated {size_mb}MB of ciphertext for NIST tests")

# def test_chi_square(keys):
#     """Test uniform distribution of ciphertext bytes
    
    
#     """
    
#     cipher = CryptoCube(keys, mode="bytes")
    
#     # Generate 10,000 ciphertext blocks
#     byte_counts = [0] * 256
#     ranks = []
#     for _ in range(500):
#         print(_)
#         plaintext = os.urandom(29)
#         ciphertext, iv = cipher.encrypt(plaintext)
        
#     # for block in ciphertext:
#         block_byte_data = permutation_to_bytes(ciphertext)
#         ranks.append(perm_to_int(ciphertext))
#         for byte in block_byte_data:
#             byte_counts[byte] += 1

#     # Test against uniform distribution
#     expected = [sum(byte_counts) / 256] * 256
#     chi2, p_value = chisquare(byte_counts, expected)
    
#     print(f"Chi-square: {chi2:.2f}, p-value: {p_value:.4f}")
#     assert p_value > 0.01, "Non-uniform distribution detected!"
#     print("✓ Chi-square test passed")



def test_position_uniformity(cipher, num_samples=1000):
    """
    Test if each position in the permutation has uniform distribution.
    
    This is the CORRECT analogue of byte-frequency testing for permutations.
    
    For a good permutation cipher:
    - Position 0 should have all 54 symbols equally likely
    - Position 1 should have all 54 symbols equally likely
    - ... and so on
    
    Expected: p-value > 0.01 for each position
    """
    print("="*70)
    print("TEST 1: Position-Level Uniformity")
    print("="*70)
    print("Question: Does each position see all 54 symbols uniformly?")
    print()
    
    # Count symbol occurrences at each position
    position_counts = [Counter() for _ in range(N)]
    
    for i in range(num_samples):
        print(i)
        plaintext = os.urandom(29)
        ciphertext, iv = cipher.encrypt(plaintext)
        
        # Count symbols at each position
        for pos, symbol in enumerate(ciphertext):
            position_counts[pos][symbol] += 1
    
    # Chi-square test for each position
    failed_positions = []
    p_values = []
    
    for pos in range(N):
        observed = [position_counts[pos].get(sym, 0) for sym in _ELEMENTS]
        expected = [num_samples / N] * N
        
        chi2, p_value = chisquare(observed, expected)
        p_values.append(p_value)
        
        if p_value < 0.01:
            failed_positions.append(pos)
    
    # Results
    print(f"Samples tested: {num_samples}")
    print(f"Positions tested: {N}")
    print(f"P-value range: [{min(p_values):.4f}, {max(p_values):.4f}]")
    print(f"Failed positions (p < 0.01): {len(failed_positions)}")
    
    if len(failed_positions) == 0:
        print("✓ PASS: All positions show uniform distribution")
        return True
    else:
        print(f"✗ FAIL: Positions {failed_positions[:5]}... show bias")
        return False
# Then run NIST suite (C program):
# ./assess 80000000  # for 10MB file

def main()->None:
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    cipher = CryptoCube(KEYS1,"bytes",whitten=False)
    test_position_uniformity(cipher, 10000)

if __name__ == "__main__":
    main()


