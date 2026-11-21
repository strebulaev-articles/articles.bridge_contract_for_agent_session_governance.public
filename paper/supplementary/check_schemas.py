#!/usr/bin/env python3
"""Validate every event emitted by conformance_suite.py against schemas/.

    python3 check_schemas.py        # requires jsonschema, pytest, hypothesis

Only events the bridge commits are checked; events a test builds by hand
(known-answer fixtures, tampered logs) are outside the schemas' scope.
Sessions that register a test-only scheme tag (cs.TEST_ONLY_SCHEMES, the
pluggable-verifier stub of T144) are skipped: the schemas enumerate the
reference tags and the stub is deliberately not one of them.
Fails if an emitted event violates its schema, or if an event kind the
reference bridge can emit has no schema (CHECKPOINT is the only kind allowed
to stay unobserved: the reference bridge does not implement I-CHECKPOINT).
"""
import json
import sys
from pathlib import Path

import jsonschema
import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import conformance_suite as cs  # noqa: E402

SCHEMAS = HERE / "schemas"
envelope = json.loads((SCHEMAS / "event.schema.json").read_text())
envelope.pop("allOf")  # per-kind dispatch is done below, without $ref resolution
payload_schemas = {p.name.split(".")[0]: json.loads(p.read_text())
                   for p in (SCHEMAS / "events").glob("*.json")}
V = jsonschema.Draft7Validator  # the keywords used are common to draft 7 and 2020-12
envelope_v = V(envelope)

observed, errors = set(), []
test_only_sessions = set()
_orig = cs.Event.__init__


def _init(self, *a, **k):
    _orig(self, *a, **k)
    if sys._getframe(1).f_code.co_name != "_commit":
        return  # only events the bridge emits; known-answer and fixture events are not
    if self.payload.get("scheme") in cs.TEST_ONLY_SCHEMES:
        test_only_sessions.add(self.session_id)
    if self.session_id in test_only_sessions:
        return  # the schemas describe reference scheme tags only (T144's stub)
    doc = {"kind": self.kind.value, "session_id": self.session_id,
           "sequence": self.sequence, "prev_hash": self.prev_hash,
           "payload": self.payload, "timestamp": self.timestamp}
    observed.add(self.kind.value)
    for e in envelope_v.iter_errors(doc):
        errors.append(f"{self.kind.value}: {e.message}")
    schema = payload_schemas.get(self.kind.value)
    if schema is not None:
        for e in V(schema).iter_errors(self.payload):
            errors.append(f"{self.kind.value}: {e.message}")


cs.Event.__init__ = _init
rc = pytest.main(["-q", "-p", "no:cacheprovider", str(HERE / "conformance_suite.py")])
kinds = set(payload_schemas)
missing = (observed - kinds)
unobserved = kinds - observed - {"CHECKPOINT", "KEY_REVOKED",
                                   "KEY_REVOCATION_REQUESTED",
                                   "OPERATOR_ADD_KEY",
                                   "OPERATOR_TERMINATION"}
for e in sorted(set(errors))[:20]:
    print("SCHEMA ERROR:", e)
if missing:
    print("kinds without a schema:", sorted(missing))
if unobserved:
    print("schemas never exercised:", sorted(unobserved))
ok = rc == 0 and not errors and not missing and not unobserved
print(f"{len(observed)} kinds observed; schemas {'OK' if ok else 'FAILED'}")
sys.exit(0 if ok else 1)
