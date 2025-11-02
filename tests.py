from crypto_engine import CryptoCube
from helper import perm_to_byte, SOLVED_KEY_CUBE, KEY_CUBE1, KEY_CUBE2
from magiccube import Cube as mCube
import os
from math import log, log2, log10
from statistics import stdev
from pprint import pprint
import random
import numpy as np

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

        return frequencies, move_count
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
        # summarized_results = []
        # for trial in range(self.trials):
        #     print(f"Starting trial {trial+1}/{self.trials}...")
        #     frequencies = self.move_distribution()
        #     standard_frequencies = self.standard_move_distribution()
        #     standard_frequencies = {k: standard_frequencies[k] for k in frequencies.keys()}
        #     kl_divergence = 0
        #     for p, q in zip(frequencies.values(), standard_frequencies.values()):
        #         kl_divergence += p * log(p/q, 2)  # KL Divergence formula
        #     result = {f"Trial {trial}" : kl_divergence}
        #     summarized_results.append(result)
        #     print(f"Completed trial {trial+1}/{self.trials}...")

        # print(f"Completed {self.trials} trials of {self.runs} runs each.")
        # self.results = summarized_results
        # return summarized_results
        
        summarized_results = []
        frequency_tables = []
    
        for trial in range(self.trials):
            print(f"Starting trial {trial+1}/{self.trials}...")
            
            frequencies, move_count = self.move_distribution()
            frequency_tables.append((frequencies,move_count))
            # Use theoretical uniform instead of scramble
            standard_frequencies = {move: 1/12 for move in 
                        ['R', "R'", 'L', "L'",
                            'U', "U'",  'D', "D'",
                            'F', "F'", 'B', "B'"]}
            
            #                   IDK WHICH ONE TO USE
            #
            # #scrambler frequencies 
            # standard_frequencies = self.standard_move_distribution()
            # standard_frequencies = {k: standard_frequencies[k] for k in frequencies.keys()}
            
            # Handle missing moves with epsilon
            epsilon = 1e-10
            all_moves = set(frequencies.keys()) | set(standard_frequencies.keys())
            
            kl_divergence = 0
            for move in all_moves:
                p = frequencies.get(move, epsilon)
                q = standard_frequencies.get(move, epsilon)
                if q == epsilon:
                    ...
                if p > epsilon:
                    kl_divergence += p * log(p/q, 2)
            
            summarized_results.append(kl_divergence)
            print(f"Completed trial {trial+1}/{self.trials}...")
        
        # Calculate summary statistics
        result = {
            "mean_kl_divergence": sum(summarized_results) / len(summarized_results),
            "stdev_kl_divergence": stdev(summarized_results) if len(summarized_results) > 1 else 0,
            "min_kl_divergence": min(summarized_results),
            "max_kl_divergence": max(summarized_results),
            "individual_trials": summarized_results,
            "frequency_distribution_tables": frequency_tables
        }
        
        self.results = result
        return result
    
    
class PositionalDivergence:
    def __init__(self, runs=100, trials=1):
        self.runs = runs
        self.trials = trials
        self.results = {}
        self.distribution_table = {}
        self.total_length = 0
    def distibution_table(self, randomizer=True):
        key = mCube(3, SOLVED_KEY_CUBE)
        if randomizer:
            key = mCube(3, KEY_CUBE1)

        crypticCube = CryptoCube(key, mode="bytes")
        distributions = {}
        
        for run_num in range(self.runs):
            print(f"run {run_num+1}/{self.runs}...")
            plaintext = os.urandom(25)
            _, ciphertext = crypticCube.encrypt(plaintext)
            
            for i, v in enumerate(ciphertext):
                pos_key = str(i)
                if pos_key not in distributions:
                    distributions[pos_key] = {
                        "values": [],
                        "frequencies": {},
                    }
                
                distributions[pos_key]["values"].append(v)
                if v not in distributions[pos_key]["frequencies"]:
                    distributions[pos_key]["frequencies"][v] = 0
                distributions[pos_key]["frequencies"][v] += 1
        
        # Calculate probabilities after all runs
        for pos_key, data in distributions.items():
            total = len(data["values"])
            data["probabilities"] = {
                v: count/total 
                for v, count in data["frequencies"].items()
            }
        
        return distributions
    def bootstrap(self, kl_values):
        n_postions = len(kl_values)
        bootstrap_means = []
    
        for _ in range(self.runs):
            sample = np.random.choice(kl_values, size=n_postions, replace=True)
            bootstrap_means.append(np.mean(sample))
        
        bootstrap_means = np.array(bootstrap_means)

        lower = np.percentile(bootstrap_means, 2.5)
        upper = np.percentile(bootstrap_means, 97.5)


        return lower, upper


    def do_test(self):
        summarized_results = []
        
        for trial in range(self.trials):
            print(f"Starting trial {trial+1}/{self.trials}...")
            self.total_length = 0  # Reset for each trial
            distribution_tables = []
            distribution = self.distibution_table()
            distribution_tables.append(distribution)
            
            kl_divergences = []
            position_samples = []
            
            for i, data in distribution.items():
                num_unique = len(data["frequencies"])
                uniform_prob = 1.0 / num_unique
                epsilon = 1e-10
                
                divergence = 0
                for prob in data["probabilities"].values():
                    if prob > 0:
                        divergence += prob * log2((prob + epsilon) / uniform_prob)
                
                kl_divergences.append(divergence)
                position_samples.append(len(data["values"]))

                bootstrap_ci = self.bootstrap(kl_divergences)
            
            result = {
                "mean_kl_divergence": sum(kl_divergences) / len(kl_divergences),
                "median_kl_divergence": sorted(kl_divergences)[len(kl_divergences)//2],
                "max_kl_divergence": max(kl_divergences),
                "stdev_kl_divergence": stdev(kl_divergences) if len(kl_divergences) > 1 else 0,
                "positions_analyzed": len(kl_divergences),
                "min_samples_per_position": min(position_samples),
                "max_samples_per_position": max(position_samples),
                "raw" :kl_divergences,
                "bootstrap_ci": {"lower": bootstrap_ci[0], "upper": bootstrap_ci[1]},
                "distribution_tables": distribution_tables
            }
            
            
            summarized_results.append(result)
            print(f"Completed trial {trial+1}/{self.trials}...")
        
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
                        "raw" : raw_results["avalanche"]["results"],
                        "mean" : avalanche_mean,
                        "percent" : avalanche_percent,
                        "stdev" : avalanche_stdev
        },
                   "key_sensitivity" : {
                        "raw" : raw_results["key_sensitivity"]["results"],
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
    #sample test run
    test = PositionalDivergence(runs=  100,trials=1)
    pprint(test.do_test())
