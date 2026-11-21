"""RFC 8785 (JSON Canonicalization Scheme) for the value types the contract uses.

Supported values: null, booleans, strings (any Unicode scalar values),
integers within the IEEE-754 safe range (|n| <= 2**53), finite floats,
arrays (lists or tuples) and objects with string keys.  Anything else
(NaN, infinities, integers beyond 2**53, non-string keys, lone surrogates)
raises ``ValueError``: a canonical form for it would not be portable.

Rules implemented, each pinned by a known-answer vector
(``vectors/bytes_kat.json``):

* object members sorted by the UTF-16 code units of their names (RFC 8785
  section 3.2.3), which differs from Unicode code point order for
  supplementary-plane characters;
* strings escaped as RFC 8785 section 3.2.2.2: ``"`` ``\\`` and the controls
  ``\\b \\t \\n \\f \\r`` in short form, every other control character
  below U+0020 as lower-case ``\\u00xx``, all else (non-ASCII, U+007F,
  U+2028) emitted as raw UTF-8;
* numbers as ECMAScript ``Number.prototype.toString`` (section 3.2.2.3):
  ``1.0`` is ``1``, ``-0.0`` is ``0``, ``1e21`` is ``1e+21``.
"""
from __future__ import annotations

import math
from typing import Any

_SHORT = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x09: "\\t",
          0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}
MAX_SAFE_INT = 2 ** 53


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c in _SHORT:
            out.append(_SHORT[c])
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(x: float) -> str:
    """ECMAScript Number-to-string for a finite double (RFC 8785 3.2.2.3)."""
    if not math.isfinite(x):
        raise ValueError("NaN and infinities have no canonical form")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    # shortest round-trip digits and decimal exponent from repr
    mantissa, _, exp = ("%r" % abs(x)).partition("e")
    int_part, _, frac = mantissa.partition(".")
    digits = (int_part + frac).lstrip("0")
    n = len(int_part) + (int(exp) if exp else 0)
    # leading zeros removed from the front shift the point
    n -= len(int_part + frac) - len((int_part + frac).lstrip("0"))
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + body


def _emit(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > MAX_SAFE_INT:
            raise ValueError("integer beyond 2**53 is not portable")
        return str(v)
    if isinstance(v, float):
        return _number(v)
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_emit(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
        keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_string(k) + ":" + _emit(v[k])
                              for k in keys) + "}"
    raise ValueError(f"no canonical JSON form for {type(v).__name__}")


def canonicalize(value: Any) -> bytes:
    """The RFC 8785 canonical bytes of ``value`` (UTF-8)."""
    return _emit(value).encode("utf-8")
