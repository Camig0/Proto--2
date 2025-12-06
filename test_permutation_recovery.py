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
    
    Args:
        cipher: CryptoCube instance
        samples: Number of attack attempts
    
    Returns:
        dict: {
            'attack_successful': bool,
            'success_rate': float,
            'recovered_permutations': int,
            'details': list of attack results
        }
    """
    successful_attacks = 0
    details = []
    
    for attempt in range(samples):
        # Step 1: Attacker knows a plaintext-ciphertext pair
        known_plaintext = bytes(range(54))  # Known pattern
        
        try:
            # Encrypt with CTR mode to get first block
            ciphertext, IV = cipher.encrypt_ctr(known_plaintext)
            

            ciphertext_blocks = []
            for i in range(0,len(ciphertext), cipher.BLOCK_SIZE):
                block = ciphertext[i:i + cipher.BLOCK_SIZE]
                ciphertext_blocks.append(block)

            known_ciphertext = ciphertext_blocks[0]
            
            # Step 2: Attacker attempts to recover the permutation
            # The cipher applies: ciphertext[i] = plaintext[perm[i]]
            # So we need to find: perm[i] = position where ciphertext[i] appears in plaintext
            
            recovered_perm = []
            for ct_byte in known_ciphertext:
                # Find where this ciphertext byte came from in plaintext
                try:
                    source_pos = known_plaintext.index(ct_byte)
                    recovered_perm.append(source_pos)
                except ValueError:
                    # Byte not found - permutation recovery failed for this position
                    recovered_perm.append(-1)
            
            # Step 3: Use recovered permutation to decrypt a DIFFERENT message
            secret_message = b"Secret data that attacker shouldn't see!!" + b"\x00" * 13
            secret_ciphertext, same_IV = cipher.encrypt_ctr(secret_message)
            
            secret_ciphertext_blocks = []
            for i in range(0,len(ciphertext), cipher.BLOCK_SIZE):
                block = ciphertext[i:i + cipher.BLOCK_SIZE]
                secret_ciphertext_blocks.append(block)


            secret_ciphertext = secret_ciphertext_blocks[0]
            
            # Apply recovered permutation (inverse operation)
            inverse_perm = [-1] * 54
            for new_pos, old_pos in enumerate(recovered_perm):
                if old_pos != -1 and old_pos < 54:
                    inverse_perm[old_pos] = new_pos
            
            # Attempt to decrypt using recovered permutation
            attempted_decrypt = bytearray(54)
            recovery_success = True
            for i in range(54):
                if inverse_perm[i] != -1:
                    attempted_decrypt[i] = secret_ciphertext[inverse_perm[i]]
                else:
                    recovery_success = False
                    break
            
            # Check if attack succeeded
            if recovery_success and bytes(attempted_decrypt[:41]) == secret_message[:41]:
                successful_attacks += 1
                details.append({
                    'attempt': attempt,
                    'status': 'ATTACK SUCCESSFUL - CIPHER BROKEN',
                    'recovered_bytes': 41,
                    'permutation_valid': True
                })
            else:
                details.append({
                    'attempt': attempt,
                    'status': 'Attack failed',
                    'recovery_success': recovery_success,
                    'permutation_valid': all(p != -1 for p in recovered_perm)
                })
                
        except Exception as e:
            print(f"Caught Error: {e.__class__.__name__}")
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
        'VERDICT': 'CIPHER BROKEN' if successful_attacks > 0 else 'Passed (permutation not recoverable)'
    }


def test_iv_reuse_vulnerability(cipher: CryptoCube, samples: int = 20):
    """
    Demonstrate that IV reuse leaks information (this SHOULD show leakage).
    
    Args:
        cipher: CryptoCube instance
        samples: Number of IV reuse tests
    
    Returns:
        dict: {
            'leakage_detected': bool,
            'identical_permutations': int,
            'details': list
        }
    """
    identical_count = 0
    details = []
    
    for i in range(samples):
        IV = os.urandom(16)
        
        msg1 = b"Message One" + b"\x00" * 43
        msg2 = b"Message Two" + b"\x00" * 43
        
        # Encrypt both with same IV
        ct1, _ = cipher.encrypt(msg1, IV=IV, block=0)
        ct2, _ = cipher.encrypt(msg2, IV=IV, block=0)
        
        # Check if the permutation is the same
        # In a secure cipher, we'd analyze XOR of ciphertexts
        # For your cipher, we check if same permutation was used
        
        # Simplified check: If we can find positional relationships
        # We'll check if patterns are preserved
        pattern_preserved = False
        
        # Check if bytes at same positions in plaintext appear at same relative positions in ciphertext
        for pos in range(min(11, 54)):  # Check first 11 positions of known data
            if msg1[pos] == msg2[pos]:
                if ct1[pos] == ct2[pos]:
                    pattern_preserved = True
                    break
        
        # Better test: Check if the INDEX mapping is identical
        # Try to find where msg1[0] went in ct1 vs where msg2[0] went in ct2
        try:
            # This is a heuristic - in practice, full permutation analysis needed
            msg1_positions = [ct1.index(msg1[j].to_bytes(1, 'big')) if msg1[j:j+1] in ct1 else -1 for j in range(11)]
            msg2_positions = [ct2.index(msg2[j].to_bytes(1, 'big')) if msg2[j:j+1] in ct2 else -1 for j in range(11)]
            
            # If positions match, same permutation was used
            if msg1_positions == msg2_positions and -1 not in msg1_positions[:5]:
                identical_count += 1
                pattern_preserved = True
        except:
            pass
        
        details.append({
            'test': i,
            'IV': IV.hex()[:16],
            'pattern_preserved': pattern_preserved,
            'same_permutation_likely': pattern_preserved
        })
    
    return {
        'leakage_detected': identical_count > samples * 0.5,
        'identical_permutations': identical_count,
        'percentage': (identical_count / samples) * 100,
        'details': details,
        'VERDICT': 'IV reuse leaks information (as expected)' if identical_count > 0 else 'No obvious leakage detected'
    }


def test_deterministic_keystream(cipher: CryptoCube, samples: int = 50):
    """
    Verify that the same IV+block produces the same keystream permutation.
    
    Args:
        cipher: CryptoCube instance
        samples: Number of IV+block combinations to test
    
    Returns:
        dict: {
            'consistent': bool,
            'consistency_rate': float,
            'details': list
        }
    """
    consistent = 0
    inconsistent = 0
    details = []
    
    for i in range(samples):
        IV = os.urandom(16)
        block_num = random.randint(0, 100)
        
        # Encrypt same plaintext twice with same IV+block
        plaintext = bytes(range(54))
        
        ct1, _ = cipher.encrypt(plaintext, IV=IV, block=block_num)
        ct2, _ = cipher.encrypt(plaintext, IV=IV, block=block_num)
        
        if ct1 == ct2:
            consistent += 1
        else:
            inconsistent += 1
            details.append({
                'IV': IV.hex()[:16],
                'block': block_num,
                'ct1': ct1[:10].hex(),
                'ct2': ct2[:10].hex()
            })
    
    return {
        'consistent': inconsistent == 0,
        'consistency_rate': consistent / samples,
        'consistent_count': consistent,
        'inconsistent_count': inconsistent,
        'details': details,
        'VERDICT': 'Keystream is deterministic (expected behavior)' if inconsistent == 0 else 'WARNING: Non-deterministic keystream'
    }


def main():
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    cipher = CryptoCube(KEYS1,"bytes",whitten=True)
    results = []
    print("1")
    pprint(test_permutation_recovery_attack(cipher))
    print("2")
    pprint(test_iv_reuse_vulnerability(cipher))
    print("3")
    pprint(test_deterministic_keystream(cipher))
    

    



if __name__ == "__main__":
    main()