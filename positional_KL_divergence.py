from crypto_engine import CryptoCube
from helper import perm_to_byte, SOLVED_KEY_CUBE, KEY_CUBE1, KEY_CUBE2
from magiccube import Cube as mCube 
import os
from math import log, log10, log2
from statistics import stdev



# Collect ciphertexts from many encryptions.

# For each position 
# 𝑖: build a frequency table of which sticker appears there.

# Compute KL divergence against uniform.

# Also run chi-square test for statistical significance.

# Aggregate results across positions (mean/variance of KL).

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
            print(f"run {_+1}/{self.runs}...")
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


if __name__ == "__main__":
    from pprint import pprint #just for testing
    TRIALS = 5
    test = PositionalDivergence(runs=1_000, trials= 5)
    results = test.do_test()
    pprint(results, indent=4)
    