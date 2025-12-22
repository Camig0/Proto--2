from magiccube import Cube as mCube
from crypto_engine import CryptoCube
import os
import scipy
from scipy.stats import chisquare, chi2
from helper import _ELEMENTS,N
import math
from collections import Counter, defaultdict
import numpy as np

from typing import Callable, Any, Dict, List

from pprint import pprint

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from logger import log_to_file

from datetime import datetime

import base64



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
        
        plaintext = os.urandom(1) * 53  # Random 54 bytes
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
                  "p values (0-53)": p_values
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
    plaintext_len: int = 53
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

def cryptocube_wrapper(pt):
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




def byte_uniformity_from_file(file_path: str, block_size: int = 54, alpha: float = 0.01) -> dict:
    """
    Test byte uniformity per position across all blocks in a file.
    """
    print("="*70)
    print("TEST: Byte-Level Position Uniformity (From File)")
    print("="*70)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    num_blocks = len(data) // block_size
    print(f"File size: {len(data)} bytes")
    print(f"Total blocks: {num_blocks} (block size: {block_size})")
    print(f"Analysis covers {num_blocks * block_size} bytes\n")
    
    position_counts = [Counter() for _ in range(block_size)]
    
    # Process blocks
    for block_idx in range(num_blocks):
        if block_idx % 10000 == 0 and block_idx > 0:
            print(f"Processed {block_idx}/{num_blocks} blocks...")
            
        block_start = block_idx * block_size
        block = data[block_start:block_start + block_size]
        
        for pos in range(block_size):
            byte_val = block[pos]
            position_counts[pos][byte_val] += 1
    
    # Chi-square tests per position
    expected_freq = num_blocks / 256.0
    chi2_values = []  # FIX: Use different name
    p_values = []
    failed_positions = []
    
    for pos in range(block_size):
        observed = [position_counts[pos].get(val, 0) for val in range(256)]
        expected = [expected_freq] * 256
        
        chi2_stat, p_value = chisquare(observed, expected)  # FIX: Store as chi2_stat
        chi2_values.append(chi2_stat)  # FIX: Append to chi2_values
        p_values.append(p_value)
        
        if p_value < alpha:
            failed_positions.append(pos)
    
    # Global chi-square test (USES the distribution)
    global_chi2 = sum(chi2_values)
    global_df = block_size * 255  # 54 * 255 = 13,770
    
    # FIX: Now chi2 refers to the distribution, not the statistic
    global_p_value = 1 - chi2.cdf(global_chi2, global_df)
    
    # Bonferroni correction
    bonferroni_threshold = alpha / block_size
    
    result = {
        "test": "byte uniformity from file",
        "file_path": file_path,
        "methodology": {
            "hypothesis": "H₀₂: At least one position is non-uniform",
            "test_statistic": "Chi-square per position + global sum",
            "degrees_of_freedom": 255,
            "alpha_per_test": alpha,
            "bonferroni_corrected_alpha": bonferroni_threshold,
            "global_test_df": global_df
        },
        "summary": {
            "total_blocks": num_blocks,
            "block_size": block_size,
            "chi2_range": f"{min(chi2_values):.2f} to {max(chi2_values):.2f}",
            "p_value_range": f"{min(p_values):.6f} to {max(p_values):.6f}",
            "global_chi2_sum": global_chi2,
            "global_p_value": global_p_value,
            "status": "PASS" if global_p_value > alpha else "FAIL"
        },
        "details": {
            "chi2_values": chi2_values,  # FIX: Use chi2_values
            "p_values": p_values,
            "failed_positions": failed_positions,
            "bonferroni_threshold": bonferroni_threshold
        }
    }
    
    print(f"\nGlobal χ² sum: {global_chi2:.2f} (df={global_df})")
    print(f"Global p-value: {global_p_value:.6f}")
    print(f"Bonferroni threshold: {bonferroni_threshold:.6f}")
    
    return result

def shannon_entropy_with_sem(data: bytes) -> tuple[float, float]:
    """
    Compute entropy and its standard error of measurement.
    SEM ≈ sqrt( [∑p_i(log₂p_i)² - (∑p_i log₂p_i)²] / n )
    """
    n = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    
    H = 0.0
    H_sq_term = 0.0  # For variance calculation
    
    for count in freq:
        if count == 0:
            continue
        p = count / n
        log_p = math.log2(p)
        H -= p * log_p
        H_sq_term += p * (log_p ** 2)
    
    # Variance of entropy estimator
    variance = (H_sq_term - H ** 2) / n
    sem = math.sqrt(max(variance, 0))  # Handle floating point negatives
    
    return H, sem

def entropy_from_file(file_path: str, threshold: float = 7.99) -> dict:
    """
    Calculate Shannon entropy with confidence interval for the entire file.
    """
    print("="*70)
    print("TEST: Shannon Entropy (From File)")
    print("="*70)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    print(f"File size: {len(data)} bytes")
    
    # Calculate entropy and SEM
    overall_entropy, sem = shannon_entropy_with_sem(data)
    
    # 99.9% confidence interval
    z = 3.3  # 99.9% confidence
    ci_lower = overall_entropy - z * sem
    ci_upper = overall_entropy + z * sem
    
    # Degrees of freedom (for theoretical reference)
    df = 255  # 256 byte values - 1
    
    result = {
        "test": "entropy test from file",
        "file_path": file_path,
        "methodology": {
            "hypothesis": "H₀₂: Mean entropy < 7.99 bits/byte (biased)",
            "alternative": "Hₐ₂: Mean entropy ≥ 7.99 bits/byte (indistinguishable)",
            "test_statistic": "Shannon entropy",
            "degrees_of_freedom": df,
            "confidence_level": 0.999,
            "z_score": z
        },
        "summary": {
            "total_bytes": len(data),
            "entropy_bits_per_byte": overall_entropy,
            "standard_error": sem,
            "ci_99.9%": f"[{ci_lower:.6f}, {ci_upper:.6f}]",
            "threshold": threshold,
            "status": "PASS" if overall_entropy >= threshold else "FAIL"
        },
        "details": {
            "byte_frequency": [data.count(i) for i in range(256)],
            "entropy_variance_estimate": sem ** 2
        }
    }
    
    print(f"\nEntropy: {overall_entropy:.6f} ± {sem:.6f} bits/byte")
    print(f"99.9% CI: [{ci_lower:.6f}, {ci_upper:.6f}]")
    print(f"Threshold: {threshold} bits/byte")
    
    if overall_entropy >= threshold:
        print("✓ PASS: Entropy meets cryptographic threshold")
    else:
        print(f"✗ FAIL: Entropy below threshold")
    
    return result

def full_test_from_file(file_path: str, block_size: int = 54) -> dict:
    """Run both tests on a file."""
    r1 = entropy_from_file(file_path)
    r2 = byte_uniformity_from_file(file_path, block_size)
    
    return {
        "entropy_test": r1,
        "byte_uniformity_test": r2
    }





def full_test(samples:int = 1000):
    r1 = test_byte_position_uniformity(cryptocube_wrapper, samples)
    r2 = entropy_test_cipher(cryptocube_wrapper, samples, 53)
    return {"byte uniformity": r1,
            "entropy":r2}

def main()->None:
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    cipher = CryptoCube(KEYS1,"bytes",whitten=True)
    results = []

    result = full_test_from_file("data.bin")
    # result = test_byte_position_uniformity(crptocube_wrapper, 1000)
    today = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"{today}.json"
    path = f"stat_tests/{file_name}"
    log_to_file(path, result)


    # pprint(entropy_test_cipher(cipher.encrypt,1000,54))
    # pprint(test_byte_position_uniformity(cipher, num_samples= 10000))


if __name__ == "__main__":
    main()


