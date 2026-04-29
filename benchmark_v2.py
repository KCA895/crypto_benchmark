import os
import time
import statistics
import pandas as pd
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

def run_benchmark():
    # Variasi ukuran payload sesuai permintaan reviewer
    payload_sizes = {
        "1KB": 1024,
        "10KB": 10240,
        "100KB": 102400,
        "1MB": 1048576
    }
    
    iterations = 1000
    warmup = 10 # Pemanasan untuk menghilangkan noise awal
    results = []

    print("Generating keys...")
    fernet_key = Fernet.generate_key()
    f = Fernet(fernet_key)

    chacha_key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(chacha_key)

    aesgcm_key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(aesgcm_key)

    print("Starting benchmark. This may take a few minutes...\n")

    for size_name, size_bytes in payload_sizes.items():
        print(f"Testing Payload Size: {size_name}...")
        data = os.urandom(size_bytes)

        # ---------------------------------------------------------
        # 1. FERNET (AES-128-CBC + HMAC + Base64)
        # ---------------------------------------------------------
        f_enc_sample = f.encrypt(data)
        f_overhead = ((len(f_enc_sample) - size_bytes) / size_bytes) * 100
        
        f_latencies = []
        for i in range(iterations + warmup):
            start = time.perf_counter()
            enc = f.encrypt(data)
            dec = f.decrypt(enc)
            end = time.perf_counter()
            if i >= warmup:
                f_latencies.append((end - start) * 1000) # Convert to ms

        results.append({
            "Algorithm": "Fernet",
            "Payload Size": size_name,
            "Avg Latency (ms)": round(statistics.mean(f_latencies), 4),
            "Std Dev (ms)": round(statistics.stdev(f_latencies), 4),
            "Throughput (OPS)": round(1000 / statistics.mean(f_latencies), 2),
            "Overhead (%)": round(f_overhead, 2)
        })

        # ---------------------------------------------------------
        # 2. ChaCha20-Poly1305 (Raw AEAD)
        # ---------------------------------------------------------
        nonce_c = os.urandom(12)
        c_enc_sample = chacha.encrypt(nonce_c, data, None)
        # Overhead AEAD = MAC tag (16 bytes) + Nonce (12 bytes) yang dikirim bersama payload
        c_overhead = (((len(c_enc_sample) + len(nonce_c)) - size_bytes) / size_bytes) * 100

        c_latencies = []
        for i in range(iterations + warmup):
            nonce = os.urandom(12) # Generate nonce per encryption (best practice)
            start = time.perf_counter()
            enc = chacha.encrypt(nonce, data, None)
            dec = chacha.decrypt(nonce, enc, None)
            end = time.perf_counter()
            if i >= warmup:
                c_latencies.append((end - start) * 1000)

        results.append({
            "Algorithm": "ChaCha20-Poly1305",
            "Payload Size": size_name,
            "Avg Latency (ms)": round(statistics.mean(c_latencies), 4),
            "Std Dev (ms)": round(statistics.stdev(c_latencies), 4),
            "Throughput (OPS)": round(1000 / statistics.mean(c_latencies), 2),
            "Overhead (%)": round(c_overhead, 2)
        })

        # ---------------------------------------------------------
        # 3. AES-GCM (Raw AEAD) - KOMPARATOR BARU
        # ---------------------------------------------------------
        nonce_a = os.urandom(12)
        a_enc_sample = aesgcm.encrypt(nonce_a, data, None)
        a_overhead = (((len(a_enc_sample) + len(nonce_a)) - size_bytes) / size_bytes) * 100

        a_latencies = []
        for i in range(iterations + warmup):
            nonce = os.urandom(12)
            start = time.perf_counter()
            enc = aesgcm.encrypt(nonce, data, None)
            dec = aesgcm.decrypt(nonce, enc, None)
            end = time.perf_counter()
            if i >= warmup:
                a_latencies.append((end - start) * 1000)

        results.append({
            "Algorithm": "AES-GCM",
            "Payload Size": size_name,
            "Avg Latency (ms)": round(statistics.mean(a_latencies), 4),
            "Std Dev (ms)": round(statistics.stdev(a_latencies), 4),
            "Throughput (OPS)": round(1000 / statistics.mean(a_latencies), 2),
            "Overhead (%)": round(a_overhead, 2)
        })

    # Output Results
    df = pd.DataFrame(results)
    print("\n--- BENCHMARK RESULTS ---")
    print(df.to_string(index=False))
    
    df.to_csv("benchmark_results_v2.csv", index=False)
    print("\n[SUCCESS] Results saved to 'benchmark_results_v2.csv'")

if __name__ == "__main__":
    run_benchmark()