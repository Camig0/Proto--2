from crypto_engine import CryptoCube
from helper import perm_to_byte, SOLVED_KEY_CUBE, KEY_CUBE1, KEY_CUBE2
from magiccube import Cube as mCube
import os
from math import log
from statistics import stdev

#Collect A_moves sequences from many encryptions.

# Tokenize them into individual moves.

# Count frequency of each move.

# Compare against uniform expectation using KL divergence or chi-square test.

# Optionally: measure average length of sequences and see if distribution is consistent.


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
    

if __name__ == "__main__":
    from pprint import pprint
    test = MoveDistributionTest(runs=1_000,trials=5)
    test.standard_move_distribution()
    pprint(test.do_test())