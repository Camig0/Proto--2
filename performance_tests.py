import json
import time
import os

# ---------------------------------------------------
# BENCHMARK WITH CIPHER REUSE (MOST ACCURATE)
# ---------------------------------------------------

def benchmark_aes128_accurate(plaintext_dataset):
    print("\n==== BENCHMARKING AES-128 (ACCURATE - CIPHER REUSE) ====")
    results = {}

    key = get_random_bytes(16)
    
    for fname, dataset in plaintext_dataset.items():
        print(f"\nRunning dataset: {fname}")

        total_bytes = 0
        encryption_times = []
        
        # Create ONE cipher for all messages of same size
        # (This is realistic - in practice you'd reuse cipher state)
        messages = [bytes.fromhex(pt["data_hex"]) for pt in dataset["plaintexts"]]
        
        # Warmup run (exclude from timing)
        cipher_warmup = AES.new(key, AES.MODE_CTR)
        _ = cipher_warmup.encrypt(messages[0])
        
        # Actual measurement
        for i, msg in enumerate(messages, start=1):
            # Create fresh cipher for each message (CTR mode requirement)
            # But this mimics real-world usage
            cipher = AES.new(key, AES.MODE_CTR)
            
            # Measure ONLY encryption
            start = time.perf_counter()
            ciphertext = cipher.encrypt(msg)
            end = time.perf_counter()
            
            encryption_times.append(end - start)
            total_bytes += len(msg)

            if i % 50 == 0 or i == len(messages):
                print(f"  Processed {i}/{len(messages)} plaintexts...")

        # Statistics
        total_time = sum(encryption_times)
        avg_time = sum(encryption_times) / len(encryption_times)
        min_time = min(encryption_times)
        max_time = max(encryption_times)
        throughput = total_bytes / total_time

        print(f"  Done. Total Time = {total_time:.6f}s, Throughput = {throughput/1e6:.2f} MB/s")

        results[fname] = {
            "total_plaintexts": len(messages),
            "total_bytes": total_bytes,
            "message_size_bytes": len(messages[0]),
            "total_time_sec": total_time,
            "avg_time_per_message_us": avg_time * 1e6,
            "min_time_per_message_us": min_time * 1e6,
            "max_time_per_message_us": max_time * 1e6,
            "throughput_bytes_per_sec": throughput,
            "throughput_MB_per_sec": throughput / 1e6,
            "throughput_Gbps": (throughput * 8) / 1e9
        }

    # Save results
    os.makedirs(RESULT_DIR, exist_ok=True)
    outpath = os.path.join(RESULT_DIR, "AES128_results_ACCURATE.json")
    with open(outpath, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[SAVED] AES-128 Results → {outpath}\n")
    
    # Summary table
    print("\n" + "="*90)
    print("SUMMARY TABLE - AES-128 ENCRYPTION PERFORMANCE")
    print("="*90)
    print(f"{'File':<25} {'Msg Size':<12} {'Avg Time (μs)':<15} {'Throughput (MB/s)':<20}")
    print("-"*90)
    
    for fname, res in results.items():
        msg_size = res['message_size_bytes']
        avg_time = res['avg_time_per_message_us']
        throughput = res['throughput_MB_per_sec']
        print(f"{fname:<25} {msg_size:<12} {avg_time:<15.3f} {throughput:<20.2f}")
    
    print("="*90)
    print(f"\n📊 Analysis:")
    print(f"   • Smaller messages show lower throughput due to cipher setup overhead")
    print(f"   • Larger messages show true AES-128 performance")
    print(f"   • Expected AES-128-CTR throughput: 500-3000 MB/s (depends on CPU)")
    print("="*90 + "\n")
    
    return results


# Alternative: Batch encryption (most realistic for large data)
def benchmark_aes128_batch(plaintext_dataset):
    print("\n==== BENCHMARKING AES-128 (BATCH MODE) ====")
    results = {}

    key = get_random_bytes(16)
    
    for fname, dataset in plaintext_dataset.items():
        print(f"\nRunning dataset: {fname}")

        # Concatenate all messages into one big buffer
        messages = [bytes.fromhex(pt["data_hex"]) for pt in dataset["plaintexts"]]
        combined_data = b''.join(messages)
        total_bytes = len(combined_data)
        
        # Encrypt entire batch at once (most efficient)
        cipher = AES.new(key, AES.MODE_CTR)
        
        start = time.perf_counter()
        ciphertext = cipher.encrypt(combined_data)
        end = time.perf_counter()
        
        total_time = end - start
        throughput = total_bytes / total_time
        
        print(f"  Encrypted {total_bytes:,} bytes in {total_time:.6f}s")
        print(f"  Throughput: {throughput/1e6:.2f} MB/s ({throughput*8/1e9:.2f} Gbps)")

        results[fname] = {
            "total_plaintexts": len(messages),
            "total_bytes": total_bytes,
            "message_size_bytes": len(messages[0]),
            "total_time_sec": total_time,
            "throughput_MB_per_sec": throughput / 1e6,
            "throughput_Gbps": (throughput * 8) / 1e9,
            "avg_time_per_message_us": (total_time / len(messages)) * 1e6
        }

    # Save results
    os.makedirs(RESULT_DIR, exist_ok=True)
    outpath = os.path.join(RESULT_DIR, "AES128_results_BATCH.json")
    with open(outpath, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[SAVED] Batch Results → {outpath}\n")
    
    return results


# ---------------------------------------------------
# MAIN
# ---------------------------------------------------

PLAINTEXT_DIR = "plaintexts"
RESULT_DIR = "results"

PLAINTEXT_FILES = [
    "plaintexts_64.json",
    "plaintexts_256.json",
    "plaintexts_1024.json",
    "plaintexts_4096.json",
    "plaintexts_65536.json"
]

def load_plaintexts():
    datasets = {}
    for fname in PLAINTEXT_FILES:
        path = os.path.join(PLAINTEXT_DIR, fname)
        with open(path, "r") as f:
            datasets[fname] = json.load(f)
        print(f"[LOADED] {fname} (total entries: {datasets[fname]['total_entries']})")
    return datasets

if __name__ == "__main__":
    plaintexts = load_plaintexts()
    
    print("\n" + "="*90)
    print("RUNNING TWO BENCHMARKS:")
    print("1. Per-message encryption (realistic for packet-by-packet)")
    print("2. Batch encryption (realistic for bulk file encryption)")
    print("="*90)
    
    # Run both benchmarks
    results_accurate = benchmark_aes128_accurate(plaintexts)
    results_batch = benchmark_aes128_batch(plaintexts)
    
    print("\n✅ All benchmarks complete!")