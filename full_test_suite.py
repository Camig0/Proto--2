from auth_test import full_test as auth_test
from avalanche_test import full_test as avalanche_test
from bug_tests import bug_tests
from statistical_randomness_tests import full_test as statistical_randomness_test
from test_permutation_recovery import full_test as critical_tests

from test_helper import log_test

def full_test_suite():
    samples = {"Authentication": 5000,
               "Avalanche" : 5000,
               "Stat tests" : 10000,
               "Permutation Recovery" : 50,
               "IV reuse" : 50,
               "Deterministic KS" :100
               }
    runs = {"Authentication": 1,
               "Avalanche" : 5,
               "Stat tests" : 3,
               "Critical" : 3
               }
    
    print( """
=========================================================
                AUTH TEST
=========================================================""")
    
    authentication_results = auth_test(samples["Authentication"])
    print( """
=========================================================
                AVALANCHE TEST
=========================================================""")
    avalanche_results = [avalanche_test(samples["Avalanche"]) for _ in range(runs["Avalanche"])]
    print( """
=========================================================
                BUG TEST
=========================================================""")
    bug_test_results = bug_tests()
    print( """
=========================================================
                STAT TEST
=========================================================""")
    statistical_randomness_results = [statistical_randomness_test(samples["Stat tests"]) for _ in range(runs["Stat tests"])]
    print( """
=========================================================
                CRITICAL TEST
=========================================================""")
    critical_tests_results = [critical_tests(samples["Permutation Recovery"], samples["IV reuse"], samples["Deterministic KS"]) for _ in range(runs["Critical"])]

    return{
           "authentication_results": authentication_results,
           "avalanche_results" : avalanche_results,
           "bug_test_results" : bug_test_results,
           "statistical_randomness_results" : statistical_randomness_results,
           "critical_test_results" : critical_tests_results}


if __name__ == "__main__":
    results = full_test_suite()
    log_test(results, "test results")