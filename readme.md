# Benchmarking Python Cryptographic Primitives in Containerized Microservices

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository contains the replication package, source code, and raw datasets for the research paper titled: 
"Benchmarking Python Cryptographic Primitives: Fernet vs. ChaCha20-Poly1305 and AES-GCM in Containerized Microservices."

The objective of this benchmark is to evaluate the performance trade-offs (throughput, latency, and transmission overhead) of various cryptographic primitives utilizing the Python `cryptography` library within a constrained Docker environment.

## 📊 Benchmark Scope
The script tests three cryptographic primitives across four different payload sizes (1KB, 10KB, 100KB, and 1MB):
1. Fernet (High-level AES-128-CBC with HMAC-SHA256 and Base64 padding)
2. ChaCha20-Poly1305 (AEAD Stream Cipher)
3. AES-GCM (AEAD Block Cipher with hardware acceleration support)

## 🛠 Prerequisites
To reproduce this benchmark, you need to have the following installed on your host machine:
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine)
* Git

Note: The original experiment was conducted on an Apple M4 processor (ARMv9 architecture). Results may vary significantly on x86_64 architectures depending on the availability of AES-NI hardware acceleration.
