# AIR v1 AWS Build Benchmark — Retest (5-Run Aggregate)

- Date (UTC): 2026-03-01T15:19:48Z
- Instance: c6i.xlarge (Intel Xeon Platinum 8375C @ 2.90GHz)
- Binary: `ephemeralml-verify (release build)`
- Receipt size: 599 bytes
- Runs: 5, verify iterations/run: 1000
- Timing tool: hyperfine 1.19.0 (--shell=none)
- Rust: 1.93.1
- Kernel: 6.1.161-183.298.amzn2023.x86_64

## Results

| Metric | Median (us/op) | p95 (us/op) | Notes |
|---|---:|---:|---|
| SHA-256 (1 KB) | 0.920 | 0.920 | OpenSSL 3.2.2 |
| SHA-256 (4 KB) | 3.215 | 3.216 | OpenSSL 3.2.2 |
| Ed25519 sign | 31.981 | 32.043 | OpenSSL 3.2.2 |
| Ed25519 verify | 101.722 | 102.983 | OpenSSL 3.2.2 |
| AIR verify (Rust CLI, process-per-call) | 1758.077 | 1760.243 | includes process spawn |

Estimated emit crypto path median: **37.035 us/op** (p95: **37.098 us/op**).

## Comparison vs Baseline (2026-03-01T13:06:46Z)

| Metric | Baseline Median | Retest Median | Delta |
|---|---:|---:|---:|
| SHA-256 (1 KB) | 0.931 | 0.920 | -1.2% |
| SHA-256 (4 KB) | 3.227 | 3.215 | -0.4% |
| Ed25519 sign | 31.763 | 31.981 | +0.7% |
| Ed25519 verify | 102.512 | 101.722 | -0.8% |
| AIR verify (CLI) | 1533.100 | 1758.077 | +14.7% |
| Emit crypto estimate | 36.852 | 37.035 | +0.5% |

### Analysis

**Crypto primitives (SHA-256, Ed25519) reproduce within ~1%.** The underlying cryptographic
operations are stable across instances and tool versions.

**CLI process-per-call latency is +14.7% higher** than baseline. The delta is entirely in process
fork/exec/linker overhead, not in cryptographic computation. Possible causes:
- Rust 1.93.1 vs earlier toolchain (different codegen, binary size)
- AL2023 kernel 6.1.161 vs earlier kernel version
- Instance placement variance (different physical host, NUMA, cache effects)
- hyperfine --shell=none vs prior timing methodology

**The emit crypto path estimate (37.0 us) confirms that per-inference
receipt generation adds < 40 microseconds** of compute — negligible relative to any
inference workload.
