from crypto_engine import CryptoCube
from helper import perm_to_byte, SOLVED_KEY_CUBE, KEY_CUBE1, KEY_CUBE2
from magiccube import Cube as mCube
import os
from math import log
from statistics import stdev


class MoveDistributionTest:
    def __init__(self, runs=100, trials=1):
        self.runs = runs
        self.trials = trials
        self.results = []
    def move_distribution(self):
        key = mCube(3, KEY_CUBE1)
        crypticCube = CryptoCube(key, mode="bytes") 
        move_count = {}
        total = 0
        for _ in range(self.runs):
            plaintext = bytearray(os.urandom(25))
            moves, _ = crypticCube.encrypt(plaintext)
            moves = moves.split(" ")
            for move in moves:
                if move not in move_count: #adds move to move count if not already in it
                    move_count[move] = 0
                move_count[move] += 1
                total += 1
        
        
        frequencies = {move : count/total for move,count in move_count.items()}
        # for move, count in move_count.items():
        #     frequencies[move] = count/total

        return frequencies
    def standard_move_distribution(self):
        distributions = {}
        frequencies = {}
        total =  0
        for _ in range(self.runs):
            cube = mCube(3, SOLVED_KEY_CUBE)
            cube.scramble()
            moves =  " ".join([str(i) for i in cube.history()])# should be a string by now
            moves = moves.split(" ")

            for move in moves:
                if move not in distributions:
                    distributions[move] = 0
                distributions[move] += 1
                total += 1

        frequencies = {move : count/total for move,count in distributions.items()}
        # for move, count in distributions.items():
        #     frequencies[move] = count/total

        return frequencies

    def do_test(self):
        summarized_results = []
        for trial in range(self.trials):
            print(f"Starting trial {trial+1}/{self.trials}...")
            frequencies = self.move_distribution()
            standard_frequencies = self.standard_move_distribution()
            standard_frequencies = {k: standard_frequencies[k] for k in frequencies.keys()}
            kl_divergence = 0
            for p, q in zip(frequencies.values(), standard_frequencies.values()):
                kl_divergence += p * log(p/q, 2)  # KL Divergence formula
            result = {f"Trial {trial}" : kl_divergence}
            summarized_results.append(result)
            print(f"Completed trial {trial+1}/{self.trials}...")

        print(f"Completed {self.trials} trials of {self.runs} runs each.")
        self.results = summarized_results
        return summarized_results
    
    # def do_test(self):
    #     ...



class PositionalDivergence:
    def __init__(self, runs=100, trials=1):
        self.runs = runs
        self.trials = trials
        self.results = {}
        self.distribution_table = {}
        self.total_length = 0
    def distibution_table(self, randomizer=True):
        key  = mCube(3, SOLVED_KEY_CUBE)
        if randomizer:
            key = mCube(3, KEY_CUBE1)

        crypticCube = CryptoCube(key, mode="bytes")
        distributions = {}

        for _ in range(self.runs):
            plaintext = os.urandom(25)
            x, ciphertext =  crypticCube.encrypt(plaintext)
            self.total_length += len(ciphertext)

            for i,v in enumerate(ciphertext):
                if str(i) not in distributions:
                    distributions[str(i)] = {"values" : [],
                                             "frequencies" : {},
                                             "probabilities" : {}}
                distributions[str(i)]["values"].append(v)
                frequencies = distributions[str(i)]["frequencies"]
                probabilities = distributions[str(i)]["probabilities"]

                if v not in frequencies:
                    frequencies[v] = 1
                    continue
                else:
                    frequencies[v] += 1

                if v not in probabilities:
                    probabilities[v] = frequencies[v]/ self.runs
                    continue
                probabilities[v] = frequencies[v]/ self.runs
        return distributions
    
    def do_test(self):
        summarized_results = []
        for trial in range(self.trials):
            print(f"Starting trial {trial+1}/{self.trials}...")
            distribution = self.distibution_table()
            kl_divergences = []
            for i, data in distribution.items():
                divergence = []
                for prob in data["probabilities"].values():
                    divergence.append(prob * log(prob / (1/48))) # 1/48 is uniform distribution
                kl_divergences.append(sum(divergence))
                mean_kl_divergence = sum(kl_divergences)/ (len(kl_divergences))
                partial_result = {"mean_kl_divergence" : mean_kl_divergence,
                                "average_length" : self.total_length/self.runs,
                                "position_kl_divergences" : kl_divergences}

            
            means = partial_result["mean_kl_divergence"]
            stdevs = stdev(partial_result["position_kl_divergences"])
            result = {"mean_kl_divergence" : means,
                    "stdev_kl_divergence" : stdevs,
                    "average_length" : partial_result["average_length"]}
            summarized_results.append(result)
            print(f"Completed trial {trial+1}/{self.trials}...")
            
        print(f"Completed {self.trials} trials of {self.runs} runs each.")
        self.results = summarized_results
        return summarized_results



class ConfusionDiffusionTest:
    def __init__(self, runs=100, trials=1):
        self.runs = runs
        self.trials = trials
        self.results = {}
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
        summarized_results = []
        for trial in range(self.trials):
            print(f"Starting trial {trial+1}/{self.trials}...")
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
                meanA =  sum(avalanche_results)/ len(avalanche_results)
                avalanche["avalanche_percent"] = meanA/ 200 #<-- max number of bits in 25 bytes
                avalanche["mean"] = meanA
            
                key_sensitivity = raw_results["key_sensitivity"]
                key_sensitivity_results = key_sensitivity["results"]
                key_sensitivity_results.append(self.key_sensitivity())
                meanK =  sum(key_sensitivity_results)/ len(key_sensitivity_results)
                key_sensitivity["key_sensitivity_percent"] = meanK/ 200 #<-- max number of bits in 25 bytes
                key_sensitivity["mean"] = meanK

                self.results = {"avalanche" : {
                                    "avalanche_percent" : avalanche["avalanche_percent"],
                                    "mean" : meanA,
                },
                                "key_sensitivity" : {
                                    "key_sensitivity_percent" : key_sensitivity["key_sensitivity_percent"],
                                    "mean"  : meanK,
                                }}
        
            avalanche_mean = raw_results["avalanche"]["mean"]
            avalanche_percent = raw_results["avalanche"]["avalanche_percent"]
            avalanche_stdev = stdev(raw_results["avalanche"]["results"])

            key_sensitivity_mean = raw_results["key_sensitivity"]["mean"]
            key_sensitivity_percent = raw_results["key_sensitivity"]["key_sensitivity_percent"]
            key_sensitivity_stdev = stdev(raw_results["key_sensitivity"]["results"])
            results = {"avalanche" : {
                        "mean" : avalanche_mean,
                        "percent" : avalanche_percent,
                        "stdev" : avalanche_stdev
        },
                   "key_sensitivity" : {
                        "mean" : key_sensitivity_mean,
                        "percent" : key_sensitivity_percent,
                        "stdev" : key_sensitivity_stdev
                   }}
            summarized_results.append(results)
            print(f"Completed trial {trial+1}/{self.trials}...")


        print(f"Completed {self.trials} trials of {self.runs} runs each.")
        self.results = summarized_results
        return summarized_results

if __name__ == "__main__":
    ...