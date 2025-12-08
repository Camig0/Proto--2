from crypto_engine import CryptoCube
from magiccube import Cube as mCube

import os

import random
from random import randint

def flip_one_random_bit(b: bytes) -> bytes:
    if not b:
        raise ValueError("empty bytes")

    # Convert to mutable form
    ba = bytearray(b)

    # Choose a random bit index across the whole byte string
    bit_index = random.randrange(len(ba) * 8)

    byte_pos = bit_index // 8
    bit_pos  = bit_index % 8

    # Mask to flip that bit
    ba[byte_pos] ^= (1 << bit_pos)

    return bytes(ba)



def generate_ct_tag_pair(cipher,pt):
    ct , _ = cipher.encrypt(pt)
    auth_tag = cipher.generate_auth_tag(ct)
    return ct, auth_tag

def generate_ct_tag_pair_ctr(cipher:CryptoCube,pt):
    ct , _ = cipher.encrypt_ctr(pt)
    auth_tag = cipher.generate_auth_tag(ct)
    return ct, auth_tag



def test_auth(samples:int = 1000):

    failed_auth = 0
    for run in range(samples):
        if run % (samples // 20) == 0:
            print(f"{run}/{samples}")

        pt = os.urandom(randint(1,54))
        KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
        cipher = CryptoCube(KEYS1, mode="bytes")
        #generate ct and auth
        base_ct, base_auth = generate_ct_tag_pair(cipher, pt)

        # manipulate ct and generate auth then compare
        flipped_ct = flip_one_random_bit(base_ct)
        regen_auth = cipher.generate_auth_tag(flipped_ct)
        if regen_auth == base_auth:
            # add to counter
            failed_auth += 1
    
    return {"test name": "authentication test",
            "sample size" : samples,
            "failed samples": failed_auth,
            "success rate": (samples - failed_auth)/samples}

def test_auth_ctr(samples:int = 1000, max_pt_size:int = 1024):

    failed_auth = 0
    for run in range(samples):
        if run % (samples // 20) == 0:
            print(f"{run}/{samples}")

        pt = os.urandom(randint(1,max_pt_size))
        KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
        cipher = CryptoCube(KEYS1, mode="bytes")
        #generate ct and auth
        base_ct, base_auth = generate_ct_tag_pair_ctr(cipher, pt)

        # manipulate ct and generate auth then compare
        flipped_ct = flip_one_random_bit(base_ct)
        regen_auth = cipher.generate_auth_tag(flipped_ct)
        if regen_auth == base_auth:
            # add to counter
            failed_auth += 1
    
    return {"test name": "authentication test",
            "sample size" : samples,
            "failed samples": failed_auth,
            "success rate": (samples - failed_auth)/samples}

if __name__ == "__main__":
    print(test_auth(100))
    print(test_auth_ctr(100, 300))
