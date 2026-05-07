#!/usr/bin/env python3
"""
AIR v1 vector interoperability test harness.

This script verifies all AIR v1 golden vectors in vectors/ without
depending on the EphemeralML Rust codebase. It performs:

- COSE_Sign1 parsing (CBOR tag 18)
- protected header checks (alg/content_type)
- Ed25519 signature verification over COSE Sig_structure1
- AIR v1 claim validation (Layer 3)
- optional policy checks from vector verify_policy (Layer 4)

Dependencies:
  pip install cbor2 pynacl
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import cbor2
except ImportError as exc:  # pragma: no cover - import guard
    print("Missing dependency: cbor2 (pip install cbor2 pynacl)", file=sys.stderr)
    raise SystemExit(2) from exc

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except ImportError as exc:  # pragma: no cover - import guard
    print("Missing dependency: pynacl (pip install cbor2 pynacl)", file=sys.stderr)
    raise SystemExit(2) from exc


# CWT / EAT keys
CWT_ISS = 1
CWT_IAT = 6
CWT_CTI = 7
EAT_NONCE = 10
EAT_PROFILE = 265

# AIR private claim keys
AIR_MODEL_ID = -65537
AIR_MODEL_VERSION = -65538
AIR_MODEL_HASH = -65539
AIR_REQUEST_HASH = -65540
AIR_RESPONSE_HASH = -65541
AIR_ATTESTATION_DOC_HASH = -65542
AIR_ENCLAVE_MEASUREMENTS = -65543
AIR_POLICY_VERSION = -65544
AIR_SEQUENCE_NUMBER = -65545
AIR_EXECUTION_TIME_MS = -65546
AIR_MEMORY_PEAK_MB = -65547
AIR_SECURITY_MODE = -65548
AIR_MODEL_HASH_SCHEME = -65549

AIR_PROFILE_URI = "https://spec.cyntrisec.com/air/v1"
ALLOWED_MEASUREMENT_TYPES = {"nitro-pcr", "tdx-mrtd-rtmr"}
ALLOWED_MODEL_HASH_SCHEMES = {"sha256-single", "sha256-concat", "sha256-manifest"}
ALLOWED_SECURITY_MODES = {"production", "evaluation"}
MAX_RECEIPT_BYTES = 65_536

COSE_TAG_SIGN1 = 18
COSE_ALG_KEY = 1
COSE_CONTENT_TYPE_KEY = 3
COSE_ALG_EDDSA = -8
COSE_CONTENT_TYPE_CWT = 61
ALLOWED_PROTECTED_HEADER_KEYS = {COSE_ALG_KEY, COSE_CONTENT_TYPE_KEY}
ALLOWED_CLAIM_KEYS = {
    CWT_ISS,
    CWT_IAT,
    CWT_CTI,
    EAT_NONCE,
    EAT_PROFILE,
    AIR_MODEL_ID,
    AIR_MODEL_VERSION,
    AIR_MODEL_HASH,
    AIR_REQUEST_HASH,
    AIR_RESPONSE_HASH,
    AIR_ATTESTATION_DOC_HASH,
    AIR_ENCLAVE_MEASUREMENTS,
    AIR_POLICY_VERSION,
    AIR_SEQUENCE_NUMBER,
    AIR_EXECUTION_TIME_MS,
    AIR_MEMORY_PEAK_MB,
    AIR_SECURITY_MODE,
    AIR_MODEL_HASH_SCHEME,
}
ALLOWED_MEASUREMENT_KEYS = {"measurement_type", "pcr0", "pcr1", "pcr2", "pcr3", "pcr4", "pcr8"}
TEXT_BOUNDS = {
    CWT_ISS: ("iss", 256),
    AIR_MODEL_ID: ("model_id", 256),
    AIR_MODEL_VERSION: ("model_version", 128),
    AIR_POLICY_VERSION: ("policy_version", 256),
    AIR_SECURITY_MODE: ("security_mode", 64),
    AIR_MODEL_HASH_SCHEME: ("model_hash_scheme", 64),
}
TEST_SIGNING_SEED = bytes([0x2A]) * 32


@dataclass
class VerifyPolicy:
    expected_nonce: bytes | None = None
    expected_model_hash: bytes | None = None
    expected_request_hash: bytes | None = None
    expected_response_hash: bytes | None = None
    expected_platform: str | None = None
    expected_model_id: str | None = None
    expected_security_mode: str | None = None
    allow_evaluation_mode: bool = False
    max_age_secs: int = 0
    clock_skew_secs: int = 0
    require_nonce: bool = False


@dataclass
class VerificationFailure:
    layer: int
    check: str
    code: str
    reason: str


@dataclass
class VerificationResult:
    ok: bool
    failure: VerificationFailure | None = None


class AirVerifyError(Exception):
    def __init__(self, layer: int, check: str, code: str, reason: str) -> None:
        super().__init__(reason)
        self.failure = VerificationFailure(layer=layer, check=check, code=code, reason=reason)


def fail(layer: int, check: str, code: str, reason: str) -> None:
    raise AirVerifyError(layer=layer, check=check, code=code, reason=reason)


def hex_to_bytes(s: str, field: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hex") from exc


def policy_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no", ""):
            return False
    raise ValueError(f"{field} must be boolean")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_receipt_cose(receipt_bytes: bytes) -> tuple[bytes, dict[Any, Any], bytes, bytes]:
    if len(receipt_bytes) > MAX_RECEIPT_BYTES:
        fail(1, "SIZE", "RECEIPT_TOO_LARGE", f"receipt length {len(receipt_bytes)} exceeds {MAX_RECEIPT_BYTES}")

    try:
        decoded = cbor2.loads(receipt_bytes)
    except Exception as exc:
        fail(1, "COSE", "COSE_DECODE_FAILED", f"failed to decode CBOR: {exc}")

    if not isinstance(decoded, cbor2.CBORTag):
        fail(1, "COSE", "COSE_DECODE_FAILED", "top-level CBOR item is not a tag")
    if decoded.tag != COSE_TAG_SIGN1:
        fail(1, "COSE", "COSE_DECODE_FAILED", f"expected tag 18, got tag {decoded.tag}")

    value = decoded.value
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        fail(1, "COSE", "COSE_DECODE_FAILED", "COSE_Sign1 must be a 4-element array")

    protected, unprotected, payload, signature = value
    if not isinstance(protected, (bytes, bytearray)):
        fail(1, "COSE", "COSE_DECODE_FAILED", "protected header is not bstr")
    if not isinstance(unprotected, Mapping):
        fail(1, "COSE", "COSE_DECODE_FAILED", "unprotected header is not a map")
    unprotected = dict(unprotected)
    if unprotected:
        fail(1, "UNPROTECTED", "UNPROTECTED_NOT_EMPTY", "AIR v1 requires an empty unprotected header")
    if not isinstance(payload, (bytes, bytearray)) or len(payload) == 0:
        fail(1, "PAYLOAD", "MISSING_PAYLOAD", "payload missing or empty")
    if not isinstance(signature, (bytes, bytearray)):
        fail(2, "SIG", "BAD_SIG_LENGTH", "signature is not bstr")

    return bytes(protected), unprotected, bytes(payload), bytes(signature)


def cbor_read_uint(data: bytes, pos: int, ai: int, layer: int, check: str) -> tuple[int, int]:
    if ai < 24:
        return ai, pos
    if ai == 24:
        return data[pos], pos + 1
    if ai == 25:
        return int.from_bytes(data[pos : pos + 2], "big"), pos + 2
    if ai == 26:
        return int.from_bytes(data[pos : pos + 4], "big"), pos + 4
    if ai == 27:
        return int.from_bytes(data[pos : pos + 8], "big"), pos + 8
    fail(layer, check, "INDEFINITE_LENGTH_FORBIDDEN", "indefinite-length CBOR is not allowed in AIR v1")


def scan_cbor_value(data: bytes, pos: int, layer: int, check: str) -> tuple[Any, int]:
    if pos >= len(data):
        fail(layer, check, "CBOR_DECODE_FAILED", "unexpected end of CBOR data")

    first = data[pos]
    pos += 1
    major = first >> 5
    ai = first & 0x1F

    if major == 0:
        value, pos = cbor_read_uint(data, pos, ai, layer, check)
        return ("uint", value), pos
    if major == 1:
        value, pos = cbor_read_uint(data, pos, ai, layer, check)
        return ("nint", -1 - value), pos
    if major == 2:
        length, pos = cbor_read_uint(data, pos, ai, layer, check)
        value = data[pos : pos + length]
        if len(value) != length:
            fail(layer, check, "CBOR_DECODE_FAILED", "truncated byte string")
        return ("bstr", value), pos + length
    if major == 3:
        length, pos = cbor_read_uint(data, pos, ai, layer, check)
        raw = data[pos : pos + length]
        if len(raw) != length:
            fail(layer, check, "CBOR_DECODE_FAILED", "truncated text string")
        try:
            return ("tstr", raw.decode("utf-8")), pos + length
        except UnicodeDecodeError:
            fail(layer, check, "CBOR_DECODE_FAILED", "invalid UTF-8 text string")
    if major == 4:
        length, pos = cbor_read_uint(data, pos, ai, layer, check)
        values = []
        for _ in range(length):
            value, pos = scan_cbor_value(data, pos, layer, check)
            values.append(value)
        return ("array", tuple(values)), pos
    if major == 5:
        length, pos = cbor_read_uint(data, pos, ai, layer, check)
        seen = set()
        pairs = []
        for _ in range(length):
            key, pos = scan_cbor_value(data, pos, layer, check)
            if key in seen:
                fail(layer, check, "DUPLICATE_MAP_KEY", f"duplicate CBOR map key: {key!r}")
            seen.add(key)
            value, pos = scan_cbor_value(data, pos, layer, check)
            pairs.append((key, value))
        return ("map", tuple(pairs)), pos
    if major == 6:
        tag, pos = cbor_read_uint(data, pos, ai, layer, check)
        value, pos = scan_cbor_value(data, pos, layer, check)
        return ("tag", tag, value), pos
    if major == 7:
        if ai < 24:
            return ("simple", ai), pos
        if ai == 24:
            return ("simple", data[pos]), pos + 1
        if ai == 25:
            return ("float16", data[pos : pos + 2]), pos + 2
        if ai == 26:
            return ("float32", data[pos : pos + 4]), pos + 4
        if ai == 27:
            return ("float64", data[pos : pos + 8]), pos + 8
    fail(layer, check, "CBOR_DECODE_FAILED", f"unsupported CBOR major={major} ai={ai}")


def assert_no_duplicate_cbor_map_keys(encoded: bytes, layer: int, check: str) -> None:
    try:
        _value, pos = scan_cbor_value(encoded, 0, layer, check)
    except AirVerifyError:
        raise
    except Exception as exc:
        fail(layer, check, "CBOR_DECODE_FAILED", f"CBOR duplicate-key scan failed: {exc}")
    if pos != len(encoded):
        fail(layer, check, "CBOR_TRAILING_DATA", "CBOR value has trailing bytes")


def assert_deterministic_cbor(encoded: bytes, value: Any, layer: int, check: str) -> None:
    try:
        canonical = cbor2.dumps(value, canonical=True)
    except Exception as exc:
        fail(layer, check, "CBOR_DECODE_FAILED", f"canonical CBOR re-encode failed: {exc}")
    if canonical != encoded:
        fail(layer, check, "NON_DETERMINISTIC_CBOR", "CBOR value is not deterministically encoded")


def decode_protected_header(protected_bstr: bytes) -> dict[Any, Any]:
    if protected_bstr == b"":
        return {}
    assert_no_duplicate_cbor_map_keys(protected_bstr, 1, "PROTECTED_ONLY")
    try:
        hdr = cbor2.loads(protected_bstr)
    except Exception as exc:
        fail(1, "COSE", "COSE_DECODE_FAILED", f"protected header decode failed: {exc}")
    if not isinstance(hdr, Mapping):
        fail(1, "COSE", "COSE_DECODE_FAILED", "protected header is not a map")
    assert_deterministic_cbor(protected_bstr, hdr, 1, "PROTECTED_ONLY")
    hdr = dict(hdr)
    unknown = set(hdr) - ALLOWED_PROTECTED_HEADER_KEYS
    if unknown:
        fail(1, "PROTECTED_ONLY", "PROTECTED_HEADER_NOT_CLOSED", f"unknown protected header key(s): {sorted(unknown)!r}")
    return hdr


def verify_sig_structure(protected_bstr: bytes, payload: bytes, signature: bytes, public_key: bytes) -> None:
    if len(signature) != 64:
        fail(2, "SIG", "BAD_SIG_LENGTH", f"expected 64-byte Ed25519 signature, got {len(signature)}")
    if len(public_key) != 32:
        fail(2, "SIG", "SIG_FAILED", f"expected 32-byte Ed25519 public key, got {len(public_key)}")

    sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload])
    try:
        VerifyKey(public_key).verify(sig_structure, signature)
    except BadSignatureError:
        fail(2, "SIG", "SIG_FAILED", "Ed25519 verification failed")
    except Exception as exc:
        fail(2, "SIG", "SIG_FAILED", f"Ed25519 verification error: {exc}")


def ensure_type(claims: dict[Any, Any], key: int, expected: type, name: str) -> Any:
    if key not in claims:
        fail(3, name, f"MISSING_CLAIM:{name}", f"missing claim key {key}")
    value = claims[key]
    if not isinstance(value, expected):
        fail(3, name, f"WRONG_TYPE:{name}", f"claim {name} has wrong type: {type(value).__name__}")
    return value


def ensure_bstr_len(value: Any, expected_len: int, layer: int, check: str, code: str, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        fail(layer, check, code, f"{name} is not bytes")
    b = bytes(value)
    if len(b) != expected_len:
        fail(layer, check, code, f"{name} length {len(b)} != {expected_len}")
    return b


def decode_and_validate_claims(payload: bytes) -> dict[Any, Any]:
    assert_no_duplicate_cbor_map_keys(payload, 3, "CLOSED_MAP")
    try:
        claims = cbor2.loads(payload)
    except Exception as exc:
        fail(1, "CLAIMS_DECODE", "PAYLOAD_NOT_MAP", f"claims decode failed: {exc}")
    if not isinstance(claims, Mapping):
        fail(1, "CLAIMS_DECODE", "PAYLOAD_NOT_MAP", "payload is not a CBOR map")
    assert_deterministic_cbor(payload, claims, 3, "DETERMINISTIC_CBOR")
    claims = dict(claims)
    for key in claims:
        if not isinstance(key, int):
            fail(3, "CLOSED_MAP", "UNKNOWN_CLAIM_KEY", f"claim key is not an integer: {key!r}")
        if key not in ALLOWED_CLAIM_KEYS:
            fail(3, "CLOSED_MAP", "UNKNOWN_CLAIM_KEY", f"unknown claim key: {key}")

    # Layer 1-ish (parse/profile): eat_profile
    profile = ensure_type(claims, EAT_PROFILE, str, "EAT_PROFILE")
    if profile != AIR_PROFILE_URI:
        fail(1, "EAT_PROFILE", "WRONG_PROFILE", f"wrong eat_profile: {profile}")

    # Basic required standard claim types
    _ = ensure_type(claims, CWT_ISS, str, "ISS")
    iat = ensure_type(claims, CWT_IAT, int, "IAT")
    if iat < 0:
        fail(3, "IAT", "WRONG_TYPE:IAT", "iat must be unsigned")
    if iat == 0:
        fail(3, "IAT", "IAT_ZERO", "iat must not be zero")
    cti = ensure_type(claims, CWT_CTI, (bytes, bytearray), "CTI")
    cti_b = ensure_bstr_len(cti, 16, 3, "CTI", "BAD_CTI_LENGTH", "cti")
    if cti_b == b"\x00" * 16:
        fail(3, "CTI", "BAD_CTI_LENGTH", "cti is all zeros")

    # Optional nonce type
    if EAT_NONCE in claims:
        nonce = claims[EAT_NONCE]
        if not isinstance(nonce, (bytes, bytearray)):
            fail(3, "NONCE", "WRONG_TYPE:NONCE", "eat_nonce must be bytes")
        nonce_len = len(bytes(nonce))
        if nonce_len < 8 or nonce_len > 64:
            fail(3, "NONCE", "BAD_NONCE_LENGTH", f"eat_nonce length {nonce_len} is outside 8..64 bytes")

    # Required AIR claims
    _ = ensure_type(claims, AIR_MODEL_ID, str, "MODEL_ID")
    _ = ensure_type(claims, AIR_MODEL_VERSION, str, "MODEL_VERSION")
    model_hash = ensure_type(claims, AIR_MODEL_HASH, (bytes, bytearray), "MHASH_PRESENT")
    model_hash_b = ensure_bstr_len(model_hash, 32, 3, "MHASH_PRESENT", "BAD_HASH_LENGTH:model_hash", "model_hash")
    if model_hash_b == b"\x00" * 32:
        fail(3, "MHASH_PRESENT", "ZERO_MODEL_HASH", "model_hash is all zeros")

    ensure_bstr_len(
        ensure_type(claims, AIR_REQUEST_HASH, (bytes, bytearray), "REQUEST_HASH"),
        32,
        3,
        "REQUEST_HASH",
        "BAD_HASH_LENGTH:request_hash",
        "request_hash",
    )
    ensure_bstr_len(
        ensure_type(claims, AIR_RESPONSE_HASH, (bytes, bytearray), "RESPONSE_HASH"),
        32,
        3,
        "RESPONSE_HASH",
        "BAD_HASH_LENGTH:response_hash",
        "response_hash",
    )
    ensure_bstr_len(
        ensure_type(claims, AIR_ATTESTATION_DOC_HASH, (bytes, bytearray), "ATTESTATION_DOC_HASH"),
        32,
        3,
        "ATTESTATION_DOC_HASH",
        "BAD_HASH_LENGTH:attestation_doc_hash",
        "attestation_doc_hash",
    )

    _ = ensure_type(claims, AIR_POLICY_VERSION, str, "POLICY_VERSION")
    security_mode = ensure_type(claims, AIR_SECURITY_MODE, str, "SECURITY_MODE")
    if security_mode not in ALLOWED_SECURITY_MODES:
        fail(3, "SECURITY_MODE", f"UNKNOWN_SECURITY_MODE:{security_mode}", f"unknown security_mode: {security_mode}")

    for key, (name, max_len) in TEXT_BOUNDS.items():
        if key not in claims:
            continue
        value = claims[key]
        if not isinstance(value, str):
            fail(3, name.upper(), f"WRONG_TYPE:{name}", f"{name} must be a string")
        if not value:
            fail(3, name.upper(), f"EMPTY_TEXT:{name}", f"{name} must be non-empty")
        if len(value) > max_len:
            fail(3, name.upper(), f"TEXT_TOO_LONG:{name}", f"{name} length {len(value)} exceeds {max_len}")

    for key, check in [
        (AIR_SEQUENCE_NUMBER, "SEQ"),
        (AIR_EXECUTION_TIME_MS, "EXEC_MS"),
        (AIR_MEMORY_PEAK_MB, "MEM_MB"),
    ]:
        value = ensure_type(claims, key, int, check)
        if value < 0:
            fail(3, check, f"WRONG_TYPE:{check}", f"{check} must be unsigned")

    # Measurements
    measurements = dict(ensure_type(claims, AIR_ENCLAVE_MEASUREMENTS, Mapping, "MEAS"))
    unknown_measurement_keys = set(measurements) - ALLOWED_MEASUREMENT_KEYS
    if unknown_measurement_keys:
        fail(
            3,
            "CLOSED_MAP",
            "UNKNOWN_MEASUREMENT_KEY",
            f"unknown measurement key(s): {sorted(unknown_measurement_keys)!r}",
        )
    mtype = measurements.get("measurement_type")
    if not isinstance(mtype, str):
        fail(3, "MTYPE", "UNKNOWN_MTYPE:<non-string>", "measurement_type missing or not a string")
    if mtype not in ALLOWED_MEASUREMENT_TYPES:
        fail(3, "MTYPE", f"UNKNOWN_MTYPE:{mtype}", f"unknown measurement_type: {mtype}")
    for pcr in ("pcr0", "pcr1", "pcr2"):
        if pcr not in measurements:
            fail(3, "MEAS", "BAD_MEASUREMENT_LENGTH", f"missing {pcr}")
        ensure_bstr_len(measurements[pcr], 48, 3, "MEAS", "BAD_MEASUREMENT_LENGTH", pcr)
    for pcr in ("pcr3", "pcr4"):
        if pcr in measurements and measurements[pcr] is not None:
            ensure_bstr_len(measurements[pcr], 48, 3, "MEAS", "BAD_MEASUREMENT_LENGTH", pcr)
    if mtype == "tdx-mrtd-rtmr" and measurements.get("pcr8") is not None:
        fail(3, "MEAS", "TDX_PCR8_FORBIDDEN", "pcr8 is not allowed for TDX measurements")
    if "pcr8" in measurements and measurements["pcr8"] is not None:
        ensure_bstr_len(measurements["pcr8"], 48, 3, "MEAS", "BAD_MEASUREMENT_LENGTH", "pcr8")

    # Optional model_hash_scheme (fail-closed if unknown)
    if AIR_MODEL_HASH_SCHEME in claims:
        scheme = claims[AIR_MODEL_HASH_SCHEME]
        if not isinstance(scheme, str):
            fail(3, "MHASH_SCHEME", "WRONG_TYPE:MHASH_SCHEME", "model_hash_scheme must be a string")
        if scheme not in ALLOWED_MODEL_HASH_SCHEMES:
            fail(3, "MHASH_SCHEME", f"UNKNOWN_MODEL_HASH_SCHEME:{scheme}", f"unknown model_hash_scheme: {scheme}")

    return claims


def apply_policy(claims: dict[Any, Any], policy: VerifyPolicy, now_epoch: int) -> None:
    iat = int(claims[CWT_IAT])
    if policy.max_age_secs > 0:
        if iat > now_epoch + policy.clock_skew_secs:
            fail(4, "FRESH", "TIMESTAMP_FUTURE", "iat is in the future")
        age = max(0, now_epoch - iat)
        if age > policy.max_age_secs:
            fail(4, "FRESH", "TIMESTAMP_STALE", f"receipt age {age}s exceeds max {policy.max_age_secs}s")

    if policy.expected_model_hash is not None:
        actual = bytes(claims[AIR_MODEL_HASH])
        if actual != policy.expected_model_hash:
            fail(4, "MHASH", "MODEL_HASH_MISMATCH", "model_hash does not match policy")

    if policy.expected_request_hash is not None:
        actual = bytes(claims[AIR_REQUEST_HASH])
        if actual != policy.expected_request_hash:
            fail(4, "RHASH", "REQUEST_HASH_MISMATCH", "request_hash does not match policy")

    if policy.expected_response_hash is not None:
        actual = bytes(claims[AIR_RESPONSE_HASH])
        if actual != policy.expected_response_hash:
            fail(4, "OHASH", "RESPONSE_HASH_MISMATCH", "response_hash does not match policy")

    if policy.expected_model_id is not None:
        actual_id = claims[AIR_MODEL_ID]
        if actual_id != policy.expected_model_id:
            fail(4, "MODEL", "MODEL_ID_MISMATCH", "model_id does not match policy")

    actual_security_mode = claims[AIR_SECURITY_MODE]
    if policy.expected_security_mode is not None:
        if actual_security_mode != policy.expected_security_mode:
            fail(4, "SECURITY_MODE_POLICY", "SECURITY_MODE_MISMATCH", "security_mode does not match policy")
    elif actual_security_mode == "evaluation" and not policy.allow_evaluation_mode:
        fail(4, "SECURITY_MODE_POLICY", "EVALUATION_MODE_REJECTED", "evaluation receipts are not accepted by default production policy")

    if policy.expected_platform is not None and policy.expected_platform != "any":
        measurements = claims[AIR_ENCLAVE_MEASUREMENTS]
        actual_platform = measurements.get("measurement_type")
        if actual_platform != policy.expected_platform:
            fail(4, "PLATFORM", "PLATFORM_MISMATCH", "measurement_type does not match policy")

    has_nonce = EAT_NONCE in claims
    if policy.require_nonce and not has_nonce:
        fail(4, "NONCE", "NONCE_MISSING", "eat_nonce required but absent")
    if policy.expected_nonce is not None:
        if not has_nonce:
            fail(4, "NONCE", "NONCE_MISSING", "eat_nonce missing")
        actual_nonce = bytes(claims[EAT_NONCE])
        if actual_nonce != policy.expected_nonce:
            fail(4, "NONCE", "NONCE_MISMATCH", "eat_nonce does not match policy")


def build_policy(policy_obj: dict[str, Any] | None) -> VerifyPolicy:
    if not policy_obj:
        return VerifyPolicy()
    policy = VerifyPolicy()
    if "expected_nonce_hex" in policy_obj:
        policy.expected_nonce = hex_to_bytes(policy_obj["expected_nonce_hex"], "expected_nonce_hex")
    if "expected_model_hash_hex" in policy_obj:
        policy.expected_model_hash = hex_to_bytes(policy_obj["expected_model_hash_hex"], "expected_model_hash_hex")
    if "expected_request_hash_hex" in policy_obj:
        policy.expected_request_hash = hex_to_bytes(policy_obj["expected_request_hash_hex"], "expected_request_hash_hex")
    if "expected_response_hash_hex" in policy_obj:
        policy.expected_response_hash = hex_to_bytes(policy_obj["expected_response_hash_hex"], "expected_response_hash_hex")
    if "expected_platform" in policy_obj:
        policy.expected_platform = str(policy_obj["expected_platform"])
    if "expected_model_id" in policy_obj:
        policy.expected_model_id = str(policy_obj["expected_model_id"])
    if "expected_security_mode" in policy_obj:
        policy.expected_security_mode = str(policy_obj["expected_security_mode"])
    if "allow_evaluation_mode" in policy_obj:
        policy.allow_evaluation_mode = policy_bool(policy_obj["allow_evaluation_mode"], "allow_evaluation_mode")
    if "max_age_secs" in policy_obj:
        policy.max_age_secs = int(policy_obj["max_age_secs"])
    if "clock_skew_secs" in policy_obj:
        policy.clock_skew_secs = int(policy_obj["clock_skew_secs"])
    if "require_nonce" in policy_obj:
        policy.require_nonce = bool(policy_obj["require_nonce"])
    return policy


def verify_vector(vec: dict[str, Any], now_epoch: int) -> VerificationResult:
    try:
        receipt_bytes = hex_to_bytes(vec["receipt_hex"], "receipt_hex")
        pubkey_field = "public_key_hex" if "public_key_hex" in vec else "wrong_public_key_hex"
        if pubkey_field not in vec:
            raise KeyError("public_key_hex")
        public_key = hex_to_bytes(vec[pubkey_field], pubkey_field)
        policy = build_policy(vec.get("verify_policy"))

        protected_bstr, _uhdr, payload, signature = parse_receipt_cose(receipt_bytes)
        protected = decode_protected_header(protected_bstr)

        alg = protected.get(COSE_ALG_KEY)
        if alg != COSE_ALG_EDDSA:
            fail(1, "ALG", "BAD_ALG", f"alg {alg!r} != -8")

        content_type = protected.get(COSE_CONTENT_TYPE_KEY)
        if content_type != COSE_CONTENT_TYPE_CWT:
            fail(1, "CONTENT_TYPE", "BAD_CONTENT_TYPE", f"content_type {content_type!r} != 61")

        if "payload_hex" in vec:
            expected_payload = hex_to_bytes(vec["payload_hex"], "payload_hex")
            if payload != expected_payload:
                fail(1, "PAYLOAD", "PAYLOAD_NOT_MAP", "payload bytes do not match payload_hex fixture")

        claims = decode_and_validate_claims(payload)
        verify_sig_structure(protected_bstr, payload, signature, public_key)
        apply_policy(claims, policy, now_epoch)
        return VerificationResult(ok=True)
    except AirVerifyError as exc:
        return VerificationResult(ok=False, failure=exc.failure)


def sign_test_receipt(protected_bstr: bytes, unprotected: dict[Any, Any], payload: bytes) -> bytes:
    sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload])
    signature = SigningKey(TEST_SIGNING_SEED).sign(sig_structure).signature
    return cbor2.dumps(cbor2.CBORTag(COSE_TAG_SIGN1, [protected_bstr, unprotected, payload, signature]))


def run_regression_checks(vectors_dir: Path, now_epoch: int, verbose: bool) -> int:
    base = load_json(vectors_dir / "valid" / "v1-nitro-no-nonce.json")
    receipt_bytes = hex_to_bytes(base["receipt_hex"], "receipt_hex")
    protected_bstr, _unprotected, payload, signature = parse_receipt_cose(receipt_bytes)

    cases: list[tuple[str, str, dict[str, Any]]] = []

    non_empty_unprotected = dict(base)
    non_empty_unprotected["receipt_hex"] = cbor2.dumps(
        cbor2.CBORTag(COSE_TAG_SIGN1, [protected_bstr, {4: b"kid"}, payload, signature])
    ).hex()
    non_empty_unprotected.pop("payload_hex", None)
    cases.append(("non-empty-unprotected-header", "UNPROTECTED_NOT_EMPTY", non_empty_unprotected))

    oversized_receipt = dict(base)
    oversized_receipt["receipt_hex"] = ("00" * (MAX_RECEIPT_BYTES + 1))
    oversized_receipt.pop("payload_hex", None)
    cases.append(("oversized-receipt", "RECEIPT_TOO_LARGE", oversized_receipt))

    protected_map = cbor2.loads(protected_bstr)
    protected_map[99] = "extra"
    extra_protected_bstr = cbor2.dumps(protected_map, canonical=True)
    extra_protected = dict(base)
    extra_protected["receipt_hex"] = sign_test_receipt(extra_protected_bstr, {}, payload).hex()
    extra_protected["payload_hex"] = payload.hex()
    cases.append(("extra-protected-header", "PROTECTED_HEADER_NOT_CLOSED", extra_protected))

    claims = cbor2.loads(payload)
    claims[-65599] = b"extra"
    unknown_claim_payload = cbor2.dumps(claims, canonical=True)
    unknown_claim = dict(base)
    unknown_claim["receipt_hex"] = sign_test_receipt(protected_bstr, {}, unknown_claim_payload).hex()
    unknown_claim["payload_hex"] = unknown_claim_payload.hex()
    cases.append(("unknown-claim-key", "UNKNOWN_CLAIM_KEY", unknown_claim))

    duplicate_claim_payload = bytes([0xB1]) + payload[1:] + bytes.fromhex("3a0001000063647570")
    duplicate_claim = dict(base)
    duplicate_claim["receipt_hex"] = sign_test_receipt(protected_bstr, {}, duplicate_claim_payload).hex()
    duplicate_claim["payload_hex"] = duplicate_claim_payload.hex()
    cases.append(("duplicate-claim-key", "DUPLICATE_MAP_KEY", duplicate_claim))

    noncanonical_claims = dict(reversed(list(cbor2.loads(payload).items())))
    noncanonical_payload = cbor2.dumps(noncanonical_claims, canonical=False)
    noncanonical = dict(base)
    noncanonical["receipt_hex"] = sign_test_receipt(protected_bstr, {}, noncanonical_payload).hex()
    noncanonical["payload_hex"] = noncanonical_payload.hex()
    cases.append(("noncanonical-payload", "NON_DETERMINISTIC_CBOR", noncanonical))

    iat_zero_claims = cbor2.loads(payload)
    iat_zero_claims[CWT_IAT] = 0
    iat_zero_payload = cbor2.dumps(iat_zero_claims, canonical=True)
    iat_zero = dict(base)
    iat_zero["receipt_hex"] = sign_test_receipt(protected_bstr, {}, iat_zero_payload).hex()
    iat_zero["payload_hex"] = iat_zero_payload.hex()
    cases.append(("iat-zero", "IAT_ZERO", iat_zero))

    bad_nonce_claims = cbor2.loads(payload)
    bad_nonce_claims[EAT_NONCE] = b"short"
    bad_nonce_payload = cbor2.dumps(bad_nonce_claims, canonical=True)
    bad_nonce = dict(base)
    bad_nonce["receipt_hex"] = sign_test_receipt(protected_bstr, {}, bad_nonce_payload).hex()
    bad_nonce["payload_hex"] = bad_nonce_payload.hex()
    cases.append(("bad-nonce-length", "BAD_NONCE_LENGTH", bad_nonce))

    empty_text_claims = cbor2.loads(payload)
    empty_text_claims[AIR_MODEL_ID] = ""
    empty_text_payload = cbor2.dumps(empty_text_claims, canonical=True)
    empty_text = dict(base)
    empty_text["receipt_hex"] = sign_test_receipt(protected_bstr, {}, empty_text_payload).hex()
    empty_text["payload_hex"] = empty_text_payload.hex()
    cases.append(("empty-model-id", "EMPTY_TEXT:model_id", empty_text))

    unknown_measurement_claims = cbor2.loads(payload)
    measurements = dict(unknown_measurement_claims[AIR_ENCLAVE_MEASUREMENTS])
    measurements["unexpected"] = b"\x00" * 48
    unknown_measurement_claims[AIR_ENCLAVE_MEASUREMENTS] = measurements
    unknown_measurement_payload = cbor2.dumps(unknown_measurement_claims, canonical=True)
    unknown_measurement = dict(base)
    unknown_measurement["receipt_hex"] = sign_test_receipt(protected_bstr, {}, unknown_measurement_payload).hex()
    unknown_measurement["payload_hex"] = unknown_measurement_payload.hex()
    cases.append(("unknown-measurement-key", "UNKNOWN_MEASUREMENT_KEY", unknown_measurement))

    passed = 0
    print("\nAIR verifier regression checks:")
    for name, expected_code, vec in cases:
        result = verify_vector(vec, now_epoch)
        if not result.ok and result.failure is not None and result.failure.code == expected_code:
            print(f"PASS {name}: rejected with {expected_code}")
            passed += 1
            continue
        if result.ok:
            print(f"FAIL {name}: expected {expected_code}, got PASS")
        else:
            assert result.failure is not None
            print(f"FAIL {name}: expected {expected_code}, got {result.failure.code}")
            if verbose:
                print(f"  reason: {result.failure.reason}")

    print(f"Regression summary: {passed}/{len(cases)} passed")
    return 0 if passed == len(cases) else 1


def iter_vector_files(vectors_dir: Path, selected_name: str | None) -> list[Path]:
    files = sorted((vectors_dir / "valid").glob("*.json")) + sorted((vectors_dir / "invalid").glob("*.json"))
    if selected_name is None:
        return files
    filtered = [p for p in files if p.stem == selected_name or p.name == selected_name]
    if not filtered:
        raise FileNotFoundError(f"vector not found: {selected_name}")
    return filtered


def evaluate_vector(path: Path, now_epoch: int, verbose: bool) -> bool:
    vec = load_json(path)
    result = verify_vector(vec, now_epoch)
    name = vec.get("name", path.stem)

    if "expected_failure" in vec:
        expected = vec["expected_failure"]
        if result.ok:
            print(f"FAIL {name}: expected failure {expected['code']}, got PASS")
            return False
        actual = result.failure
        assert actual is not None
        ok = (
            actual.code == expected.get("code")
            and actual.check == expected.get("check")
            and actual.layer == int(expected.get("layer"))
        )
        if ok:
            print(f"PASS {name}: expected failure {actual.code} (L{actual.layer}/{actual.check})")
            if verbose:
                print(f"  reason: {actual.reason}")
            return True
        print(
            f"FAIL {name}: expected {expected.get('code')} (L{expected.get('layer')}/{expected.get('check')}), "
            f"got {actual.code} (L{actual.layer}/{actual.check})"
        )
        if verbose:
            print(f"  reason: {actual.reason}")
        return False

    # Valid vector
    if result.ok:
        print(f"PASS {name}: valid vector accepted")
        return True
    assert result.failure is not None
    print(
        f"FAIL {name}: expected PASS, got {result.failure.code} "
        f"(L{result.failure.layer}/{result.failure.check})"
    )
    if verbose:
        print(f"  reason: {result.failure.reason}")
    return False


def main(argv: list[str]) -> int:
    script_dir = Path(__file__).resolve().parent
    default_vectors = (script_dir.parent / "vectors").resolve()

    parser = argparse.ArgumentParser(description="Run AIR v1 vector interoperability checks")
    parser.add_argument("--vectors-dir", type=Path, default=default_vectors, help="Path to AIR vectors directory")
    parser.add_argument("--vector", help="Run a single vector by filename or stem")
    parser.add_argument("--now-epoch", type=int, default=int(time.time()), help="Unix time for freshness checks")
    parser.add_argument("--verbose", action="store_true", help="Print failure reasons")
    args = parser.parse_args(argv)

    try:
        files = iter_vector_files(args.vectors_dir, args.vector)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if not files:
        print(f"No vector files found under {args.vectors_dir}", file=sys.stderr)
        return 2

    print(f"AIR v1 interop test: {len(files)} vector(s) from {args.vectors_dir}")
    print(f"now_epoch={args.now_epoch}")

    passed = 0
    for path in files:
        if evaluate_vector(path, args.now_epoch, args.verbose):
            passed += 1

    total = len(files)
    failed = total - passed
    regression_failed = run_regression_checks(args.vectors_dir, args.now_epoch, args.verbose)
    print(f"\nSummary: {passed}/{total} passed, {failed} failed")
    return 0 if failed == 0 and regression_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
