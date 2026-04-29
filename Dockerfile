# Dockerfile untuk Benchmarking Cryptographic Primitives
# Merepresentasikan containerized microservice environment

FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements dan install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy benchmark script
COPY benchmark_v2.py .

# Run benchmark saat container start
CMD ["python", "benchmark_v2.py"]
