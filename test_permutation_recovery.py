import os
import time
import random
from collections import Counter
from typing import List, Tuple, Dict
import numpy as np
from scipy import stats
from magiccube import Cube as mCube

# Assuming your cipher modules are importable
from crypto_engine import CryptoCube
from helper import seeded_random_cube, _ELEMENTS

from pprint import pprint
import traceback


def test_permutation_recovery_attack(cipher: CryptoCube, samples: int = 10):
    """
    CRITICAL: Test if attacker can recover permutation from known plaintext.
    
    This is the most important test. If this fails, the cipher is broken.
    
    NOTE: Cipher accepts max 53 bytes plaintext, outputs 54 bytes ciphertext
    
    Args:
        cipher: CryptoCube instance
        samples: Number of attack attempts
    
    Returns:
        dict: Attack results
    """
    successful_attacks = 0
    details = []
    
    for attempt in range(samples):
        if attempt % (samples//100) == 0:
            print(f"{attempt}/{samples}")
        # Step 1: Attacker knows a plaintext-ciphertext pair
        # FIXED: 53 bytes max (not 54)
        known_plaintext = bytes(range(53))  # Known pattern [0,1,2,...,52]
        
        try:
            # Encrypt with CTR mode to get first block
            ciphertext, IV = cipher.encrypt_ctr(known_plaintext)
            
            # Extract first block (should be 54 bytes)
            ciphertext_blocks = []
            for i in range(0, len(ciphertext), cipher.CT_BLOCK_SIZE):
                block = ciphertext[i:i + cipher.CT_BLOCK_SIZE]
                ciphertext_blocks.append(block)

            known_ciphertext = ciphertext_blocks[0]
            
            if len(known_ciphertext) != 54:
                details.append({
                    'attempt': attempt,
                    'status': 'Error - unexpected ciphertext length',
                    'expected': 54,
                    'got': len(known_ciphertext)
                })
                continue
            
            # Step 2: Attacker attempts to recover the permutation
            # Note: Position 53 might be the length byte, so we focus on first 53 positions
            
            recovered_perm = []
            recovery_failed = False
            
            # Only analyze first 53 bytes (last byte might be length indicator)
            for i, ct_byte in enumerate(known_ciphertext[:53]):
                # Find where this ciphertext byte came from in plaintext
                try:
                    source_pos = known_plaintext.index(ct_byte)
                    recovered_perm.append(source_pos)
                except ValueError:
                    # Byte not found - permutation recovery failed for this position
                    # This is GOOD - means cipher does more than just permutation
                    recovered_perm.append(-1)
                    recovery_failed = True
            
            if recovery_failed:
                details.append({
                    'attempt': attempt,
                    'status': 'Attack failed - cipher uses substitution/transformation',
                    'recovery_success': False,
                    'permutation_valid': False
                })
                continue
            
            # Step 3: Use recovered permutation to decrypt a DIFFERENT message
            # FIXED: 53 bytes max (41 + 12 = 53)
            secret_message = b"Secret data that attacker shouldn't see!!" + bytes(range(12))
            secret_ciphertext_full, same_IV = cipher.encrypt_ctr(secret_message)
            
            # Extract blocks from secret_ciphertext
            secret_ciphertext_blocks = []
            for i in range(0, len(secret_ciphertext_full), cipher.BLOCK_SIZE):
                block = secret_ciphertext_full[i:i + cipher.BLOCK_SIZE]
                secret_ciphertext_blocks.append(block)

            secret_ciphertext = secret_ciphertext_blocks[0]
            
            # Apply recovered permutation (inverse operation)
            # Only work with first 53 bytes
            inverse_perm = [-1] * 53
            for new_pos, old_pos in enumerate(recovered_perm):
                if old_pos != -1 and old_pos < 53:
                    inverse_perm[old_pos] = new_pos
            
            # Attempt to decrypt using recovered permutation
            attempted_decrypt = bytearray(53)
            recovery_success = True
            for i in range(53):
                if inverse_perm[i] != -1:
                    attempted_decrypt[i] = secret_ciphertext[inverse_perm[i]]
                else:
                    recovery_success = False
                    break
            
            # Check if attack succeeded (check first 41 bytes of secret message)
            if recovery_success and bytes(attempted_decrypt[:41]) == secret_message[:41]:
                successful_attacks += 1
                details.append({
                    'attempt': attempt,
                    'status': ' ATTACK SUCCESSFUL - CIPHER BROKEN',
                    'recovered_bytes': 41,
                    'permutation_valid': True
                })
            else:
                details.append({
                    'attempt': attempt,
                    'status': 'Attack failed - recovered permutation invalid',
                    'recovery_success': recovery_success,
                    'permutation_valid': all(p != -1 for p in recovered_perm)
                })
                
        except Exception as e:
            print(f"Caught Error: {e.__class__.__name__}: {e}")
            traceback.print_exc()
            details.append({
                'attempt': attempt,
                'status': 'Error during attack',
                'error': str(e)
            })
    
    return {
        'attack_successful': successful_attacks > 0,
        'success_rate': successful_attacks / samples,
        'recovered_permutations': successful_attacks,
        'details': details,
        'VERDICT': ' CIPHER BROKEN - Permutation recoverable' if successful_attacks > 0 else 'Passed - Permutation not recoverable'
    }


def test_iv_reuse_vulnerability(cipher: CryptoCube, samples: int = 20):
    """
    Demonstrate that IV reuse leaks information (this SHOULD show leakage).
    
    NOTE: Cipher accepts max 53 bytes plaintext, outputs 54 bytes ciphertext
    
    Args:
        cipher: CryptoCube instance
        samples: Number of IV reuse tests
    
    Returns:
        dict: IV reuse test results
    """
    identical_count = 0
    details = []
    
    for i in range(samples):
        IV = os.urandom(16)
        
        # FIXED: Use 53-byte messages (not 54)
        # 16 + 37 = 53 bytes
        msg1 = b"AAAA_Message_One" + bytes(range(37))
        msg2 = b"BBBB_Message_Two" + bytes(range(37, 74))
        
        # Encrypt both with same IV
        ct1, _ = cipher.encrypt(msg1, IV=IV, block=0)
        ct2, _ = cipher.encrypt(msg2, IV=IV, block=0)
        
        if len(ct1) != 54 or len(ct2) != 54:
            details.append({
                'test': i,
                'status': 'Error - unexpected ciphertext length',
                'ct1_len': len(ct1),
                'ct2_len': len(ct2)
            })
            continue
        
        # Check if the permutation is the same
        pattern_preserved = False
        same_permutation = False
        
        # Test 1: Check if identical bytes at same positions remain identical
        # Only check first 53 positions (position 53 might be length byte)
        matching_positions = 0
        for pos in range(53):
            if msg1[pos] == msg2[pos]:
                if ct1[pos] == ct2[pos]:
                    matching_positions += 1
        
        if matching_positions > 0:
            pattern_preserved = True
        
        # Test 2: Try to determine if same permutation was used
        try:
            msg1_positions = []
            msg2_positions = []
            
            for j in range(min(16, len(msg1))):  # Check first 16 bytes
                # Find where msg1[j] appears in ct1
                byte_val1 = msg1[j:j+1]
                byte_val2 = msg2[j:j+1]
                
                try:
                    # Only search in first 53 bytes
                    pos1 = ct1[:53].index(byte_val1)
                    msg1_positions.append(pos1)
                except ValueError:
                    msg1_positions.append(-1)
                
                try:
                    pos2 = ct2[:53].index(byte_val2)
                    msg2_positions.append(pos2)
                except ValueError:
                    msg2_positions.append(-1)
            
            # If most positions match and no -1s in first few, same permutation likely used
            valid_positions = [(p1, p2) for p1, p2 in zip(msg1_positions[:8], msg2_positions[:8]) if p1 != -1 and p2 != -1]
            
            if len(valid_positions) >= 5:
                # Check if the mapping is identical
                matching = sum(1 for p1, p2 in valid_positions if p1 == p2)
                if matching >= len(valid_positions) * 0.8:  # 80% match
                    same_permutation = True
                    identical_count += 1
        except Exception as e:
            print(f"Position analysis error: {e}")
        
        details.append({
            'test': i,
            'IV': IV.hex()[:16],
            'pattern_preserved': pattern_preserved,
            'matching_positions': matching_positions,
            'same_permutation_likely': same_permutation
        })
    
    return {
        'leakage_detected': identical_count > 0,
        'identical_permutations': identical_count,
        'percentage': (identical_count / samples) * 100,
        'details': details,
        'VERDICT': f'IV reuse leaks information (detected in {identical_count}/{samples} cases) - This is EXPECTED for deterministic ciphers'
    }


def test_deterministic_keystream(cipher: CryptoCube, samples: int = 50):
    """
    Verify that the same IV+block produces the same keystream permutation.
    
    NOTE: Cipher accepts max 53 bytes plaintext, outputs 54 bytes ciphertext
    
    Args:
        cipher: CryptoCube instance
        samples: Number of IV+block combinations to test
    
    Returns:
        dict: Determinism test results
    """
    consistent = 0
    inconsistent = 0
    details = []
    
    for i in range(samples):
        IV = os.urandom(16)
        block_num = random.randint(0, 100)
        
        # Encrypt same plaintext twice with same IV+block
        # FIXED: 53 bytes max (not 54)
        plaintext = bytes(range(53))
        
        try:
            ct1, _ = cipher.encrypt(plaintext, IV=IV, block=block_num)
            ct2, _ = cipher.encrypt(plaintext, IV=IV, block=block_num)
            
            if ct1 == ct2:
                consistent += 1
            else:
                inconsistent += 1
                details.append({
                    'test': i,
                    'IV': IV.hex()[:16],
                    'block': block_num,
                    'ct1': ct1[:10].hex(),
                    'ct2': ct2[:10].hex(),
                    'ct1_len': len(ct1),
                    'ct2_len': len(ct2),
                    'mismatch': 'Ciphertexts differ'
                })
        except Exception as e:
            inconsistent += 1
            details.append({
                'test': i,
                'error': str(e)
            })
    
    return {
        'consistent': inconsistent == 0,
        'consistency_rate': consistent / samples,
        'consistent_count': consistent,
        'inconsistent_count': inconsistent,
        'details': details if inconsistent > 0 else [],
        'VERDICT': 'Keystream is deterministic (expected behavior)' if inconsistent == 0 else f'⚠️ WARNING: Non-deterministic keystream detected in {inconsistent}/{samples} tests'
    }


def full_test(
        perm_recovery_samples:int = 10,
          iv_reuse_samples:int = 20, 
          deterministic_key_samples:int = 50):

    KEYS1 = [
        mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), 
        mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), 
        mCube(3, "GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")
    ]
    cipher = CryptoCube(KEYS1, "bytes", whitten=True)

    perm_recovery = test_permutation_recovery_attack(cipher, perm_recovery_samples)
    iv_reuse = test_iv_reuse_vulnerability(cipher,iv_reuse_samples)
    deterministic_key = test_deterministic_keystream(cipher,deterministic_key_samples)

    return({"Permutation Recovery Test":perm_recovery,
            "IV Reuse Vulnerability":iv_reuse,
            "Deterministic Keystream Test":deterministic_key})


def main():
    # Example usage
    full_test(perm_recovery_samples=10_000)


if __name__ == "__main__":
    main()