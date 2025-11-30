from magiccube import Cube as mCube
from crypto_engine import CryptoCube
import os
import scipy
from scipy.stats import chisquare
from helper import permutation_to_bytes

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

def test_chi_square(keys):
    """Test uniform distribution of ciphertext bytes
    
    
    """
    
    cipher = CryptoCube(keys, mode="bytes")
    
    # Generate 10,000 ciphertext blocks
    byte_counts = [0] * 256
    
    for _ in range(5000):
        print(_)
        plaintext = os.urandom(29)
        ciphertext, iv = cipher.encrypt(plaintext)
        
    # for block in ciphertext:
        block_byte_data = permutation_to_bytes(ciphertext)
        for byte in block_byte_data:
            byte_counts[byte] += 1

    # Test against uniform distribution
    expected = [sum(byte_counts) / 256] * 256
    chi2, p_value = chisquare(byte_counts, expected)
    
    print(f"Chi-square: {chi2:.2f}, p-value: {p_value:.4f}")
    assert p_value > 0.01, "Non-uniform distribution detected!"
    print("✓ Chi-square test passed")

# Then run NIST suite (C program):
# ./assess 80000000  # for 10MB file

def main()->None:
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    test_chi_square(KEYS1)


if __name__ == "__main__":
    main()