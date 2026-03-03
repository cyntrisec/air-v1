# AIR v1 GCP Environment-Sensitivity Check (5-Run Aggregate)

> **Note:** This is an environment-sensitivity check, not a controlled cross-cloud
> comparison. The GCP and AWS stacks differ in OpenSSL version (3.0 vs 3.2), CPU
> generation, kernel, and distro. Direct numerical comparison is not meaningful.
> The safe claim from this data: **AIR crypto path remains in tens of microseconds
> across tested environments.**

- Date (UTC): 2026-03-01T15:45:49Z
- Cloud: GCP
- Instance: n2-standard-4 (Intel Xeon @ 2.80 GHz, 4 vCPU, 16 GB)
- Binary: `ephemeralml-verify (release build)`
- Receipt size: 599 bytes
- Runs: 5, verify iterations/run: 1000
- Timing tool: hyperfine 1.19.0 (--shell=none)
- Rust: 1.93.1
- OpenSSL: 3.0.13 (Ubuntu 24.04)
- Kernel: 6.17.0-1008-gcp

## Results

| Metric | Median (us/op) | p95 (us/op) | Notes |
|---|---:|---:|---|
| SHA-256 (1 KB) | 2.670 | 2.681 | OpenSSL 3.0.13 |
| SHA-256 (4 KB) | 9.711 | 9.735 | OpenSSL 3.0.13 |
| Ed25519 sign | 47.118 | 47.156 | OpenSSL 3.0.13 |
| Ed25519 verify | 126.873 | 127.885 | OpenSSL 3.0.13 |
| AIR verify (Rust CLI, process-per-call) | 2290.974 | 2320.010 | includes process spawn |

Estimated emit crypto path median: **62.178 us/op** (p95: **62.215 us/op**).

## AWS Reference Values (not a controlled comparison)

The table below shows AWS numbers alongside GCP for context. Because the stacks
are not controlled (different OpenSSL, CPU, kernel, distro), the deltas reflect
**host/software differences, not protocol-level differences.** Do not cite these
deltas as cloud-vs-cloud performance.

| Metric | AWS Baseline | AWS Retest | GCP | Notes |
|---|---:|---:|---:|---|
| SHA-256 (1 KB) | 0.931 | 0.920 | 2.670 | OpenSSL 3.2 vs 3.0 assembly |
| SHA-256 (4 KB) | 3.227 | 3.215 | 9.711 | OpenSSL 3.2 vs 3.0 assembly |
| Ed25519 sign | 31.763 | 31.981 | 47.118 | CPU gen + OpenSSL version |
| Ed25519 verify | 102.512 | 101.722 | 126.873 | CPU gen + OpenSSL version |
| AIR verify (CLI) | 1533.100 | 1758.077 | 2290.974 | Crypto + process spawn |
| Emit crypto est. | 36.852 | 37.035 | 62.178 | Crypto path only |

## Stack Differences Explaining Variance

| Factor | AWS (c6i.xlarge) | GCP (n2-standard-4) |
|---|---|---|
| OpenSSL | 3.2.2 (AL2023) | 3.0.13 (Ubuntu 24.04) |
| CPU | Xeon 8375C @ 2.90 GHz (Ice Lake) | Xeon @ 2.80 GHz (Cascade Lake) |
| Kernel | 6.1.161 (AL2023) | 6.17.0 (Ubuntu GCP) |
| SHA-NI / AVX-512 | 3.2 assembly exploits both | 3.0 generic x86-64-v2 codegen |

The 2.9x SHA-256 gap and ~1.5x Ed25519 gap are consistent with
OpenSSL-version and CPU-generation differences. A controlled same-stack run
(same OpenSSL build and CPU class) is required before making cloud-vs-cloud
performance claims.

## Conclusion

**AIR v1 crypto path remains in tens of microseconds across tested
environments** (~37 us on AWS with OpenSSL 3.2, ~62 us on GCP with OpenSSL 3.0).
Both are negligible relative to any inference workload. A controlled cross-cloud
comparison (same OpenSSL, same CPU class) is needed before citing specific
cloud-vs-cloud deltas.
