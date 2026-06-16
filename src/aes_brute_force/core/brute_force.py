"""
Brute-force key search for AES-128 with reduced key entropy.

Tries every key value from 0 to ``2^key_bits - 1``, decrypts the
ciphertext, and checks whether the result looks like valid plaintext
(valid PKCS#7 + high ASCII printable ratio).

Key fixes over the legacy version
----------------------------------
* PyCryptodome availability is checked **once** before the loop instead
  of raising + catching ``ImportError`` on every iteration.
* ``validate_key_bits`` is imported from ``core.constants`` (DRY).
* Uses the ``logging`` module instead of bare ``print``.
"""

from __future__ import annotations

import time
from multiprocessing import Pool, cpu_count
from typing import Callable, Dict, Optional, Tuple

from aes_brute_force.core.aes_engine import PureAES, unpad
from aes_brute_force.core.constants import (
    AES_BLOCK_SIZE,
    DEFAULT_SCORE_THRESHOLD,
    SUPPORTED_KEY_BITS,
    validate_key_bits,
)
from aes_brute_force.utils.logging import get_logger

logger = get_logger("brute_force")

# PyCryptodome (optional fast backend)
try:
    from Crypto.Cipher import AES as _CryptoAES

    _PYCRYPTODOME_OK = True
except ImportError:
    _CryptoAES = None  # type: ignore[assignment]
    _PYCRYPTODOME_OK = False

CallbackType = Callable[[int, int, float], None]
DetailCallbackType = Callable[[Dict[str, object]], None]


# ---------------------------------------------------------------------------
# Plaintext heuristics
# ---------------------------------------------------------------------------

def is_valid_plaintext(data: bytes) -> bool:
    """Return ``True`` if *data* consists of printable ASCII + whitespace."""
    if not data:
        return False
    return all(32 <= b <= 126 or b in (9, 10, 13) for b in data)


def score_plaintext(data: bytes) -> float:
    """Score in [0, 1]: ratio of printable ASCII bytes."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


# ---------------------------------------------------------------------------
# Multiprocessing worker
# ---------------------------------------------------------------------------

def _bruteforce_worker(args: Tuple[int, int, int, bytes, float, bool]) -> Dict[str, object]:
    """Scan key range ``[start, end)`` — used by ``Pool.imap_unordered``."""
    start, end, key_bits, ciphertext, threshold, fast_mode = args
    key_bytes_len = (key_bits + 7) // 8

    for i in range(start, end):
        key = i.to_bytes(key_bytes_len, "big").ljust(16, b"\x00")
        try:
            if fast_mode:
                raw = _CryptoAES.new(key, _CryptoAES.MODE_ECB).decrypt(ciphertext)  # type: ignore[union-attr]
            else:
                raw = PureAES(key).decrypt(ciphertext)
            try:
                unpadded = unpad(raw, AES_BLOCK_SIZE)
            except ValueError:
                continue
            score = score_plaintext(unpadded)
            if score >= threshold:
                try:
                    plaintext = unpadded.decode("utf-8")
                    return {
                        "found": True,
                        "key_int": i,
                        "key_hex": key[:key_bytes_len].hex().upper(),
                        "key_full_hex": key.hex().upper(),
                        "plaintext": plaintext,
                        "plaintext_score": score,
                        "keys_tested": i - start + 1,
                    }
                except UnicodeDecodeError:
                    pass
        except ValueError:
            continue

    return {"found": False, "keys_tested": end - start}


# ---------------------------------------------------------------------------
# Main brute-force entry point
# ---------------------------------------------------------------------------

def brute_force_aes(
    ciphertext: bytes,
    key_bits: int,
    callback: Optional[CallbackType] = None,
    detail_callback: Optional[DetailCallbackType] = None,
    stop_flag: Optional[object] = None,
    workers: int = 1,
    chunk_size: int = 10_000,
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
    detail_interval: Optional[int] = None,
    fast_mode: bool = False,
) -> Dict[str, object]:
    """Try all ``2^key_bits`` keys and return the first valid match."""
    validate_key_bits(key_bits)

    # FIX: Fail fast instead of raising ImportError on every iteration.
    if fast_mode and not _PYCRYPTODOME_OK:
        raise ImportError(
            "pycryptodome is required for fast mode: pip install pycryptodome"
        )

    max_keys = 1 << key_bits
    key_bytes_len = (key_bits + 7) // 8
    start_time = time.time()
    keys_tested = 0
    update_interval = max(1, min(100_000, max_keys // 100))
    if detail_interval is None:
        detail_interval = max(1, min(10_000, max_keys // 200))

    def _elapsed() -> float:
        return time.time() - start_time

    def _emit(event: str, **payload: object) -> None:
        if detail_callback is None:
            return
        current = int(payload.get("current", keys_tested) or 0)
        detail_callback({
            "event": event,
            "current": current,
            "total": max_keys,
            "elapsed": _elapsed(),
            "percent": (current / max_keys) * 100 if max_keys else 0.0,
            **payload,
        })

    def _make_result(found: bool, **kw: object) -> Dict[str, object]:
        elapsed = _elapsed()
        tested = int(kw.get("keys_tested", keys_tested) or keys_tested)
        kps = tested / elapsed if elapsed > 0 else 0
        return {
            "found": found,
            "key_int": kw.get("key_int"),
            "key_hex": kw.get("key_hex"),
            "key_full_hex": kw.get("key_full_hex"),
            "plaintext": kw.get("plaintext"),
            "plaintext_score": kw.get("plaintext_score", 0.0),
            "elapsed_seconds": elapsed,
            "keys_tested": tested,
            "keys_per_second": kps,
            "total_keyspace": max_keys,
            "percent_searched": (tested / max_keys) * 100 if max_keys else 100.0,
        }

    # --- Multiprocessing path ---
    if workers > 1:
        logger.info("Starting multiprocessing brute force (%d workers, %d-bit)", workers, key_bits)
        _emit("start", workers=workers, key_bits=key_bits, keyspace=max_keys,
              mode="multiprocessing", fast_mode=fast_mode)

        safe_workers = max(1, min(workers, cpu_count() or 1))
        ranges = [
            (i, min(i + chunk_size, max_keys), key_bits, ciphertext, score_threshold, fast_mode)
            for i in range(0, max_keys, chunk_size)
        ]
        pool = Pool(processes=safe_workers)
        try:
            for result in pool.imap_unordered(_bruteforce_worker, ranges):
                if stop_flag is not None and stop_flag.is_set():
                    pool.terminate()
                    break
                keys_tested += result.get("keys_tested", 0)
                if callback is not None:
                    callback(keys_tested, max_keys, _elapsed())
                _emit("chunk_done", current=keys_tested, keys_tested=keys_tested, workers=safe_workers)
                if result.get("found"):
                    pool.terminate()
                    _emit("found", current=keys_tested, **{
                        k: result[k] for k in ("key_int", "key_hex", "key_full_hex", "plaintext", "plaintext_score")
                    })
                    result.pop("keys_tested", None)
                    result.pop("found", None)
                    return _make_result(True, keys_tested=keys_tested, **result)
        finally:
            # We explicitly DO NOT call pool.join() here.
            # On Windows, calling pool.join() from a child thread after pool.terminate()
            # can cause a deadlock if the pool's internal queues are still full.
            pool.terminate()

        _emit("exhausted", current=keys_tested, keys_tested=keys_tested)
        return _make_result(False)

    # --- Sequential path ---
    logger.info("Starting sequential brute force (%d-bit, keyspace=%d)", key_bits, max_keys)
    _emit("start", current=0, workers=1, key_bits=key_bits, keyspace=max_keys,
          key_bytes_len=key_bytes_len, score_threshold=score_threshold,
          mode="sequential", fast_mode=fast_mode)

    for i in range(max_keys):
        if stop_flag is not None and stop_flag.is_set():
            _emit("stopped", current=keys_tested, keys_tested=keys_tested)
            break

        current = i + 1
        key_part = i.to_bytes(key_bytes_len, "big")
        key = key_part.ljust(16, b"\x00")
        key_hex = key_part.hex().upper()

        if detail_callback is not None and (i == 0 or current % detail_interval == 0):
            _emit("trying", current=current, key_int=i, key_hex=key_hex,
                  key_full_hex=key.hex().upper())

        try:
            if fast_mode:
                raw = _CryptoAES.new(key, _CryptoAES.MODE_ECB).decrypt(ciphertext)  # type: ignore[union-attr]
            else:
                raw = PureAES(key).decrypt(ciphertext)

            try:
                unpadded = unpad(raw, AES_BLOCK_SIZE)
            except ValueError:
                continue

            score = score_plaintext(unpadded)
            preview = unpadded[:80].decode("utf-8", errors="replace")
            _emit("padding_valid", current=current, key_int=i, key_hex=key_hex,
                  plaintext_preview=preview, plaintext_score=score)

            if score >= score_threshold:
                try:
                    plaintext = unpadded.decode("utf-8")
                    _emit("found", current=current, key_int=i, key_hex=key_hex,
                          key_full_hex=key.hex().upper(), plaintext=plaintext, plaintext_score=score)
                    return _make_result(True, key_int=i, key_hex=key_hex,
                                        key_full_hex=key.hex().upper(), plaintext=plaintext,
                                        plaintext_score=score, keys_tested=current)
                except UnicodeDecodeError:
                    pass
        except ValueError:
            continue

        keys_tested = current
        if callback is not None and keys_tested % update_interval == 0:
            callback(keys_tested, max_keys, _elapsed())

    _emit("exhausted", current=keys_tested, keys_tested=keys_tested)
    return _make_result(False)


# ---------------------------------------------------------------------------
# Time estimation
# ---------------------------------------------------------------------------

def estimate_time(key_bits: int, keys_per_second: Optional[float] = None) -> Dict[str, object]:
    """Estimate average and worst-case brute-force duration."""
    if key_bits <= 0:
        raise ValueError("key_bits must be > 0")
    keyspace = 1 << key_bits
    if keys_per_second is None or keys_per_second <= 0:
        keys_per_second = 50_000
    avg = (keyspace / 2) / keys_per_second
    worst = keyspace / keys_per_second

    def _fmt(s: float) -> str:
        if s < 60:
            return f"{s:.1f}s"
        if s < 3600:
            return f"{s / 60:.1f}m"
        if s < 86400:
            return f"{s / 3600:.1f}h"
        if s < 86400 * 365:
            return f"{s / 86400:.1f}d"
        return f"{s / 86400 / 365:.2e}y"

    return {
        "key_bits": key_bits,
        "keyspace": keyspace,
        "keyspace_formatted": f"2^{key_bits} = {keyspace:,}",
        "keys_per_second": keys_per_second,
        "avg_time_seconds": avg,
        "worst_time_seconds": worst,
        "avg_time_formatted": _fmt(avg),
        "worst_time_formatted": _fmt(worst),
    }
