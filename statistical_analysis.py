from scipy.stats import chisquare

from scipy.stats import binomtest

from scipy import stats
import numpy as np

from logger import load_json, log_to_file

#byte uniformity
def stat_uniformity(data):
    
    p_values = data["details"]["p values (0-53)"]

    # Count failures (p ≤ 0.01)
    alpha = 0.01
    failed_positions = [p for p in p_values if p <= alpha]
    fail_rate = len(failed_positions) / len(p_values)

    # Expected: ≤5% failures by chance
    expected_fail_rate = 0.05

    if fail_rate <= expected_fail_rate:
        decision = "Reject H₀₂ᵦ: Byte distribution is uniform"
    else:
        decision = "Fail to reject H₀₂ᵦ: Byte distribution is non-uniform"

    return {"byte uniformit stat" : {
        "failed" : failed_positions,
        "fail rate" : fail_rate,
        "expected fail rate" : expected_fail_rate,
        "verdict" : decision
    }}


# shannon entropy
def stat_entropy(data):
    entropies = data["details"]["entropies"]

    mean_entropy = np.mean(entropies)
    std_entropy = np.std(entropies, ddof=1)
    threshold = 7.92  # 99% of theoretical max (8.0)

    # One-sample t-test
    t_stat, p_value = stats.ttest_1samp(entropies, 8.0)

    decision = "Reject H₀₂: High entropy" if mean_entropy >= threshold else "Fail to reject H₀₂: Low entropy"

    print(f"Mean entropy: {mean_entropy:.3f} bits/byte")
    print(f"Threshold: {threshold} bits/byte")
    print(f"Decision: {decision}")
    

#Authentication
def stat_auth(results):
    total = results['Non-CTR Authentication']['sample size']
    failures = results['Non-CTR Authentication']['failed samples']
    
    max_failure_rate = float('inf')  # Default for failed case
    if failures == 0:
        # Rule of three: 95% confidence that failure rate < 3/total
        max_failure_rate = 3.0 / total
        decision = f"REJECT H₀₆: Failure rate < {max_failure_rate:.6f} (95% confidence)"
    else:
        decision = f"FAIL TO REJECT H₀₆: {failures/total:.2%} failure rate observed"
    
    return {"stat_verify_auth": {"sample size": total, "verdict": decision, "max_failure_rate": max_failure_rate}}

#diffusion
def stat_diffusion(data):
    hamming_distances = data["diffusion test"]["details"]["hamming distance"]
    hd = np.array(hamming_distances)
    
    
    mean_hd = np.mean(hd)
    std_hd = np.std(hd, ddof=1)
    n = len(hd)
    
    # 99.9% Confidence interval (3.3 sigma)
    ci_margin = 3.3 * (std_hd / np.sqrt(n))
    ci_lower = mean_hd - ci_margin
    ci_upper = mean_hd + ci_margin
    
    # Equivalence test: Is CI entirely within [0.49, 0.51]?
    if ci_lower >= 0.49 and ci_upper <= 0.51:
        decision = "REJECT H₀₃"
        verdict = "PASS: Diffusion achieved (±1% bias)"
    else:
        decision = "FAIL TO REJECT H₀₃"
        verdict = f"FAIL: CI [{ci_lower:.4f}, {ci_upper:.4f}] outside target"
    
    return {"Diffusion_stat": {  # Fixed: underscore
        "mean_hd": mean_hd,
        "ci_99.9%": f"[{ci_lower:.4f}, {ci_upper:.4f}]",  # Fixed: label
        "verdict": verdict,
        "note": "Equivalence test (CI method)"
    }}

# key confusion
def stat_confusion(data):
    hamming_distances = data["confusion test"]["details"]["hamming distance"]
    hd = np.array(hamming_distances)
    
    
    mean_hd = np.mean(hd)
    std_hd = np.std(hd, ddof=1)
    n = len(hd)
    
    # 99.9% Confidence interval (3.3 sigma)
    ci_margin = 3.3 * (std_hd / np.sqrt(n))
    ci_lower = mean_hd - ci_margin
    ci_upper = mean_hd + ci_margin
    
    # Equivalence test: Is CI entirely within [0.49, 0.51]?
    if ci_lower >= 0.49 and ci_upper <= 0.51:
        decision = "REJECT H₀₃"
        verdict = "PASS: Confusion achieved (±1% bias)"
    else:
        decision = "FAIL TO REJECT H₀₃"
        verdict = f"FAIL: CI [{ci_lower:.4f}, {ci_upper:.4f}] outside target"
    
    return {"Confusion_stat": {  # Fixed: underscore
        "mean_hd": mean_hd,
        "ci_99.9%": f"[{ci_lower:.4f}, {ci_upper:.4f}]",  # Fixed: label
        "verdict": verdict,
        "note": "Equivalence test (CI method)"
    }}

def verify_permutation_recovery(data):

    num_attempts = len(data["details"])
    num_successes = data["recovered_permutations"]

    if num_successes == 0:
        max_success_prob = 3.0 / num_attempts
        return {
            "decision": "REJECT H₀₂",
            "verdict": "PASS: Permutation not recoverable",
            "max_recovery_prob": max_success_prob
        }
    else:
        return {
            "decision": "FAIL TO REJECT H₀₂",
            "verdict": "FAIL: Recovery attack succeeded",
            "success_rate": num_successes / num_attempts
        }


def verify_iv_reuse(data, cipher_type: str = "nonce_based"):
    """
    cipher_type: "nonce_based" (CTR, GCM) or "deterministic" (CBC, your cube)
    """
    num_iv_pairs = len(data["details"])
    num_leaks = data["identical_permutations"]
    
    if cipher_type == "deterministic":
        # For deterministic ciphers, IV reuse producing same output is EXPECTED
        return {
            "decision": "N/A (deterministic cipher)",
            "verdict": "Test not applicable - deterministic ciphers reuse IV",
            "note": "Use nonce-based mode instead"
        }
    
    # For nonce-based ciphers:
    if num_leaks == 0:
        return {
            "samples" : num_iv_pairs,
            "decision": "REJECT H₀₂",
            "verdict": "PASS: No information leakage"
        }
    else:
        return {
            "decision": "FAIL TO REJECT H₀₂",
            "verdict": "FAIL: IV reuse leak detected",
            "leak_rate": num_leaks / num_iv_pairs
        }

def full_analysis():
    # Authentication
    results_location = "FINAL RESULTS/"
    auth_data = load_json(results_location + "authentication_results.json")
    auth = stat_auth(auth_data["data"])
    print(auth)

    # Avalanche Shenanigans
    avalanche_data = load_json(results_location + "avalanche_results.json")
    avalanche_data:list[dict] = avalanche_data["1"]
    diffusion_results = []
    confusion_results = []
    for data in avalanche_data:
        diffusion = stat_diffusion(data)
        confusion = stat_confusion(data)
        diffusion_results.append(diffusion)
        confusion_results.append(confusion)
    ...
    #Permutation Recovery & IV reuse
    critical_test_data = load_json(results_location + "critical_results.json")
    critical_test_data:list[dict] = critical_test_data["1"]
    perm_recovery_results = []
    iv_reuse_results = []
    for batch_data in critical_test_data:
        perm_recovery_data = batch_data["Permutation Recovery Test"]
        iv_reuse_data = batch_data["IV Reuse Vulnerability"]
        
        perm_recovery = verify_permutation_recovery(perm_recovery_data)
        iv_reuse = verify_iv_reuse(iv_reuse_data, cipher_type="nonce based")
        perm_recovery_results.append(perm_recovery)
        iv_reuse_results.append(iv_reuse)
    
    return{"authentication" : auth,
           "diffusion" : diffusion_results,
           "confusion" : confusion_results,
           "permutation recovery" : perm_recovery_results,
           "IV reuse" : iv_reuse_results}




if __name__ == "__main__":
    full_analysis_results = full_analysis()
    log_to_file("separated_test_results/analysis/",full_analysis_results)
    
    