import os
import random
from magiccube import Cube as mCube
from crypto_engine import CryptoCube
from helper import perm_to_byte, SOLVED_KEY_CUBE, KEY_CUBE1, KEY_CUBE2



class ConfusionDiffusionTest():
    def __init__(self, runs=100):
        self.runs = runs
        self.results = []
    def avalanche_effect(self, randomizer=False):
        #format of plaintexts  = (p1, p2) -->
        #          ciphertexts = (c1, c2)
        p1 = bytearray(os.urandom(25)) #max block size
        p2 = p1[:]
        p2[0] ^= 0b00000001
        crypticCube = CryptoCube(mCube(3, SOLVED_KEY_CUBE), mode="bytes") # randomizer off
        if randomizer:
            crypticCube = CryptoCube(mCube(3, KEY_CUBE1), mode="bytes") # randomizer on 
        _, c1 = crypticCube.encrypt(p1)
        _, c2 = crypticCube.encrypt(p2)
        c1 = perm_to_byte(c1)
        c2 = perm_to_byte(c2)

        hamming_distance = 0
        for b1, b2 in zip(c1, c2):
            hamming_distance += bin(b1 ^ b2).count("1")

        return hamming_distance
    def key_sensitivity(self):
        plaintext = bytearray(os.urandom(25))
        key1 = mCube(3, KEY_CUBE1)
        key2 = mCube(3, KEY_CUBE2)

        crypticCube1 = CryptoCube(key1, mode="bytes")
        crypticCube2 = CryptoCube(key2, mode="bytes")

        _, c1 = crypticCube1.encrypt(plaintext)
        _, c2 = crypticCube2.encrypt(plaintext)
        c1 = perm_to_byte(c1)
        c2 = perm_to_byte(c2)


        hamming_distance = 0
        for b1, b2 in zip(c1, c2):
            hamming_distance += bin(b1 ^ b2).count("1")

        return hamming_distance


    def do_test(self):
        raw_results = {
            "avalanche" : {"results":[],
                        "avalanche_percent" : 0,
                        "mean" : 0,

                        },
            "key_sensitivity" : { "results" : [],
                                 "key_sensitivity_percent" : 0,
                                 "mean"  : 0,
            }

        }
        for run in range(self.runs):
            avalanche = raw_results["avalanche"]
            avalanche_results = avalanche["results"]
            avalanche_results.append(self.avalanche_effect())
            mean =  sum(avalanche_results)/ len(avalanche_results)
            avalanche["avalanche_percent"] = mean/ 200 #<-- max number of bits in 25 bytes
            avalanche["mean"] = mean
        
            key_sensitivity = raw_results["key_sensitivity"]
            key_sensitivity_results = key_sensitivity["results"]
            key_sensitivity_results.append(self.key_sensitivity())
            mean =  sum(key_sensitivity_results)/ len(key_sensitivity_results)
            key_sensitivity["key_sensitivity_percent"] = mean/ 200 #<-- max number of bits in 25 bytes
            key_sensitivity["mean"] = mean

            print(f"run {run}/{self.runs}...")
        return raw_results

if __name__ == "__main__":
 
    test = ConfusionDiffusionTest(runs=500)
    print(test.avalanche_effect())
    print(test.key_sensitivity())

    print(test.do_test())
