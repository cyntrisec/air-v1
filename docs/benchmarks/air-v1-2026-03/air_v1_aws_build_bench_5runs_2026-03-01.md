# AIR v1 AWS Build Benchmark (5-Run Aggregate)

- Date (UTC): 2026-03-01T13:06:46Z
- Instance: c6i.xlarge
- Binary: `ephemeralml-verify (release build)`
- Receipt size: 599 bytes
- Runs: 5, verify iterations/run: 1000

| Metric | Median (us/op) | p95 (us/op) | Notes |
|---|---:|---:|---|
| SHA-256 (1 KB) | 0.931 | 0.931 | OpenSSL 3.2.2 |
| SHA-256 (4 KB) | 3.227 | 3.227 | OpenSSL 3.2.2 |
| Ed25519 sign | 31.763 | 31.887 | OpenSSL 3.2.2 |
| Ed25519 verify | 102.512 | 103.338 | OpenSSL 3.2.2 |
| AIR verify (Rust CLI, process-per-call) | 1533.100 | 1558.608 | includes process spawn |

Estimated emit crypto path median: **36.852 us/op** (p95: **36.958 us/op**).
