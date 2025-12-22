import os
from crypto_engine import CryptoCube
from magiccube import Cube as mCube

from helper import seeded_random_cube, _MOVES


from test_helper import crptocube_wrapper, AES_wrapper, log_test

import random

from pprint import pprint

from base64 import b64encode


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

def hamming_dist(a:bytes,b:bytes):
    assert isinstance(a, bytes) and isinstance(b,bytes)
    hamming_distance = 0
    for _a, _b in zip(a,b):
        hamming_distance += bin(_a ^ _b).count("1")
    return   hamming_distance / (len(a) * 8)  

def diffusion_test(cipher, samples:int = 1000, pt_size:int = 53):
    # generate PT
    hamming_distances = []
    ciphertexts = []
    for run in range(samples):
        if run % (samples / 200) == 0:
            print(f"{run}/{samples}")
        PT = os.urandom(pt_size)
        # generate bit flipped PT
        PT_flipped = flip_one_random_bit(PT)

        # generate CT of PT and PT_flipped
        CT = cipher(PT)

        CT_flipped = cipher(PT_flipped)

        # pass CT and CT_flipped to a hamming distance counter
        H = hamming_dist(CT, CT_flipped)
        hamming_distances.append(H)

        # add CT to collection

        ciphertexts.append((CT,CT_flipped))

        # add the hamming distance to the collection
    return {
        "test_name" : "diffusion test",
        "samples" : samples,
        "Plaintext size" :pt_size,
        "avg hamming distance": (sum(hamming_distances)/len(hamming_distances)),
        "details": {
            "hamming distance" : hamming_distances,
            "ciphertext (base, flipepd)" : {i:(b64encode(data[0]).decode("ascii"), b64encode(data[1]).decode("ascii")  )for i,data in enumerate(ciphertexts)}
            }
            
            }

def key_confusion(cipher:callable, samples:int = 1000, pt_size:int = 53):
    #generate PT
    PT = os.urandom(pt_size)
    hamming_distances = []
    ciphertexts = []
    for run in range(samples):
        if run % (samples / 200) == 0:
            print(f"{run}/{samples}")

        #generate base master keys
        base_keys:list[mCube] = [seeded_random_cube(os.urandom(16)) for _ in range (3)] # always use 3 for purposes of the study
        #copy master keys and do small change
        
        random_move = random.randint(0,len(_MOVES))
        flipped_key = mCube(3, base_keys[0].get())
        flipped_key.rotate(_MOVES[random_move-1])
        flipped_keys:list[mCube] = [flipped_key] + base_keys[1:]
        #Generate CT of base keys and flipped keys
        base_CT = cipher(PT, base_keys, True)
        flipped_CT = cipher(PT, flipped_keys, True)
        #Get hamming distance
        H = hamming_dist(base_CT, flipped_CT)
        #Add CT pair to collection

        ciphertexts.append((base_CT, flipped_CT))

        #Add hamming distance to collection 

        hamming_distances.append(H)

    #return summary of results CT collection * Hamming Distance Collection
    return {
        "test_name" : "key confusion test",
        "samples" : samples,
        "Plaintext size" :pt_size,
        "avg hamming distance": (sum(hamming_distances)/len(hamming_distances)),
        "details": {
            "hamming distance" : hamming_distances,
            "ciphertext (base, flipepd)" : {i:(b64encode(data[0]).decode("ascii"), b64encode(data[1]).decode("ascii")  ) for i,data in enumerate(ciphertexts)}
            }
            
            }

def full_test(samples:int = 1000):
    r1 = diffusion_test(crptocube_wrapper,samples)
    r2 = key_confusion(crptocube_wrapper,samples)
    return {"diffusion test":r1,
            "confusion test":r2}

if __name__ == "__main__":
    result = full_test(5000)
    log_test(result,"test results/Avalanche tests")
