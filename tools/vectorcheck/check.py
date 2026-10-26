#!/usr/bin/env python3
"""Independent offline oracle for spec/swarm-envelope-2.md, never an effect permit.

Claims: derive canonical bytes, strict crypto, ordered authorization and plans
from received inputs. Limits: provider and journal evidence are fixture inputs;
no live storage, phone, time collector, carrier or consumer is qualified.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
except ImportError:
    ec = None


class Refusal(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Refusal(code)


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64(text, length=None):
    require(isinstance(text, str) and re.fullmatch(r"[A-Za-z0-9_-]*", text), "envelope_malformed")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, base64.binascii.Error):
        raise Refusal("envelope_malformed") from None
    require(b64(raw) == text and (length is None or len(raw) == length), "envelope_malformed")
    return raw


def pairs(items):
    result = {}
    for key, val in items:
        require(key not in result, "envelope_malformed")
        result[key] = val
    return result


def integer(token):
    require(token != "-0" and abs(int(token)) <= 9007199254740991, "envelope_malformed")
    return int(token)


def no_number(_):
    raise Refusal("envelope_malformed")


def values(value, depth=0, max_depth=16):
    if isinstance(value, (dict, list)):
        depth += 1
        require(depth <= max_depth, "envelope_malformed")
        if isinstance(value, list):
            require(len(value) <= 64, "envelope_malformed")
            for item in value:
                values(item, depth, max_depth)
        else:
            for key, item in value.items():
                values(key, depth, max_depth)
                values(item, depth, max_depth)
    elif isinstance(value, str):
        require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "envelope_malformed")
        require(len(value.encode("utf-8")) <= 8192, "envelope_malformed")


def parse(raw, max_depth=16):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=no_number, parse_constant=no_number)
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("envelope_malformed") from None
    values(value, max_depth=max_depth)
    return value


def ccj(value):
    # Python sorts Unicode scalar strings, emits shortest integers/minimal escapes.
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def exact(value, names):
    require(type(value) is dict and set(value) == set(names.split()), "envelope_malformed")


def timestamp(text):
    require(isinstance(text, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", text), "envelope_malformed")
    try:
        value = dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise Refusal("envelope_malformed") from None
    require(value.year >= 1970, "envelope_malformed")
    return int(value.timestamp())


def hash_id(value):
    require(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "envelope_malformed")


def identifier(value, pattern=False, single=False):
    if (not isinstance(value, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in value)
            or len(value.encode("utf-8")) > 255):
        return False
    if pattern and value.endswith("/*"):
        value = value[:-2]
    expr = r"[a-z0-9-]+" if single else r"[a-z0-9-]+(?:/[a-z0-9-]+)*"
    return re.fullmatch(expr, value) is not None


def target(value, pattern=False, operator=False):
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    names = {"kind", "id", "harness", "profile"} if kind == "credential" else {"kind", "id"}
    return (isinstance(kind, str)
            and kind in ({"registration", "account"} if operator else {"credential", "station"})
            and set(value) == names
            and ((type(value["id"]) is int and 1 <= value["id"] <= 9007199254740991)
                 if kind == "registration" else identifier(value["id"], pattern))
            and (kind != "credential" or all(identifier(value[n], single=True) for n in ("harness", "profile"))))


def key_bytes(key):
    require(isinstance(key, str) and ":" in key, "envelope_malformed")
    alg, text = key.split(":", 1)
    require(alg in {"ed25519", "p256"}, "envelope_malformed")
    return alg, unb64(text, 32 if alg == "ed25519" else 33)


# Independent Ed25519 arithmetic; strict subgroup checks supplement the equation.
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, Q - 2, Q) % Q
IDENTITY = (0, 1, 1, 0)


def add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1-x1)*(y2-x2) % Q
    b = (y1+x1)*(y2+x2) % Q
    c = 2*D*t1*t2 % Q
    d = 2*z1*z2 % Q
    e, f, g, h = (b-a) % Q, (d-c) % Q, (d+c) % Q, (b+a) % Q
    return e*f % Q, g*h % Q, f*g % Q, e*h % Q


def mul(p, scalar):
    result = IDENTITY
    while scalar:
        if scalar & 1:
            result = add(result, p)
        p = add(p, p)
        scalar >>= 1
    return result


def equal(p, q):
    return (p[0]*q[2] - q[0]*p[2]) % Q == 0 and (p[1]*q[2] - q[1]*p[2]) % Q == 0


def point(raw, strict=True):
    n = int.from_bytes(raw, "little")
    y, sign = n & (2**255-1), n >> 255
    require(y < Q, "envelope_signature_invalid")
    xx = (y*y-1)*pow(D*y*y+1, Q-2, Q) % Q
    x = pow(xx, (Q+3)//8, Q)
    if x*x % Q != xx:
        x = x*pow(2, (Q-1)//4, Q) % Q
    require(x*x % Q == xx and not (x == 0 and sign), "envelope_signature_invalid")
    if x % 2 != sign:
        x = Q-x
    p = x, y, 1, x*y % Q
    if strict:
        require(not equal(p, IDENTITY) and equal(mul(p, L), IDENTITY), "envelope_signature_invalid")
    return p


BASE = point(bytes.fromhex("58" + "66"*31), False)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def verify_signature(key, sig, preimage):
    alg, public = key_bytes(key)
    if alg == "ed25519":
        a, r = point(public), point(sig[:32])
        scalar = int.from_bytes(sig[32:], "little")
        require(scalar < L, "envelope_signature_invalid")
        challenge = int.from_bytes(hashlib.sha512(sig[:32]+public+preimage).digest(), "little") % L
        require(equal(mul(BASE, scalar), add(r, mul(a, challenge))), "envelope_signature_invalid")
    else:
        require(ec is not None, "PENDING_p256_cryptography_unavailable")
        require(public[0] in (2, 3), "envelope_signature_invalid")
        try:
            obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
        except ValueError:
            raise Refusal("envelope_signature_invalid") from None
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        require(1 <= r < P256_N and 1 <= s < P256_N, "envelope_signature_invalid")
        require(s <= P256_N//2, "signature_high_s")
        try:
            obj.verify(utils.encode_dss_signature(r, s), preimage, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise Refusal("envelope_signature_invalid") from None


def schema(envelope, expected):
    exact(envelope, "version body id signatures")
    require(type(envelope["version"]) is str, "envelope_malformed")
    hash_id(envelope["id"])
    b = envelope["body"]
    common = "type aud nonce iat exp "
    extra = {"message/1": "author author_attestation action target arguments room to body_sha256",
             "grant/1": "issuer subject actions targets not_before expires depth parent caveats min_assurance",
             "operator-act/1": "operation target owner epoch action_id arguments_digest confirmed"}
    exact(b, common + extra[expected])
    require(isinstance(b["type"], str), "envelope_malformed")
    require(isinstance(b["aud"], str) and re.fullmatch(r"[!-~]{1,255}", b["aud"]), "envelope_malformed")
    unb64(b["nonce"], 16)
    start, end = timestamp(b["iat"]), timestamp(b["exp"])
    require(start < end and (expected == "grant/1" or end-start <= 120), "envelope_malformed")
    signatures = envelope["signatures"]
    require(type(signatures) is list and 1 <= len(signatures) <= 8, "envelope_malformed")
    for sig in signatures:
        exact(sig, "role key sig")
        require(isinstance(sig["role"], str), "envelope_malformed")
        key_bytes(sig["key"])
        unb64(sig["sig"], 64)
    if expected == "grant/1":
        assurance_value(b["min_assurance"], "envelope_malformed")
        key_bytes(b["issuer"])
        key_bytes(b["subject"])
        require(type(b["actions"]) is list and 1 <= len(b["actions"]) <= 64
                and all(isinstance(a, str) for a in b["actions"])
                and b["actions"] == sorted(set(b["actions"])), "envelope_malformed")
        require(type(b["targets"]) is list and 1 <= len(b["targets"]) <= 64
                and all(target(t, True) for t in b["targets"])
                and len({ccj(t) for t in b["targets"]}) == len(b["targets"]), "envelope_malformed")
        require(type(b["depth"]) is int and 0 <= b["depth"] <= 3, "envelope_malformed")
        if b["parent"] is not None:
            hash_id(b["parent"])
        require(b["not_before"] == b["iat"] and b["expires"] == b["exp"], "envelope_malformed")
        if b["caveats"] is not None:
            c = b["caveats"]
            exact(c, "lang not_before expires")
            require(c["lang"] == "caveats/v1" and start <= timestamp(c["not_before"])
                    < timestamp(c["expires"]) <= end, "envelope_malformed")
    elif expected == "operator-act/1":
        require(identifier(b["operation"].replace(".", "/")) if isinstance(b["operation"], str) else False, "envelope_malformed")
        require(target(b["target"], operator=True), "envelope_malformed")
        require(isinstance(b["owner"], str) and 1 <= len(b["owner"].encode("utf-8")) <= 255
                and isinstance(b["epoch"], str) and re.fullmatch(r"[!-~]{1,255}", b["epoch"]), "envelope_malformed")
        unb64(b["action_id"], 16)
        hash_id(b["arguments_digest"])
        require(type(b["confirmed"]) is bool, "envelope_malformed")
    else:
        require(all(type(b[n]) is str and re.fullmatch(r"[!-~]{1,255}", b[n]) for n in ("room", "to")), "envelope_malformed")
        require(type(b["body_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", b["body_sha256"]), "envelope_malformed")
        key_bytes(b["author"])
        hash_id(b["author_attestation"])
        require(isinstance(b["action"], str) and target(b["target"])
                and isinstance(b["arguments"], dict), "envelope_malformed")


def time_values(f):
    t = f.get("time")
    require(type(t) is dict and t.get("trusted") is True and t.get("fresh") is True, "time_unavailable")
    try:
        now, authority = timestamp(f.get("now")), timestamp(t.get("authority_until"))
    except Refusal:
        raise Refusal("time_unavailable") from None
    require(now < authority, "time_unavailable")
    require(f.get("watermark_available") is True, "watermark_unavailable")
    try:
        watermark = timestamp(f.get("watermark"))
    except Refusal:
        raise Refusal("watermark_unavailable") from None
    return min(now, watermark), max(now, watermark)


def window(start, end, low, high):
    require(high < timestamp(end), "expired")
    require(low >= timestamp(start), "not_yet_valid")


OWN_TAGS = {"message/1": "swarma-msg/2", "grant/1": "swarma-waggle grant/1",
            "operator-act/1": "swarma-waggle operator-act/1",
            "attestation/1": "swarma-attestation attestation/1",
            "revocation/1": "swarma-attestation revocation/1",
            "journal-entry/1": "swarma-registry journal-entry/1",
            "checkpoint/2": "swarma-registry checkpoint/2",
            "freshness/2": "swarma-registry freshness/2",
            "checkpoint/1": "swarma-registry checkpoint/1",
            "freshness/1": "swarma-registry freshness/1"}
REGISTERED_TAGS = set(OWN_TAGS.values()) | {
    "swarma-registrar registration/1", "swarma-registrar enrollment/1",
    "swarma-credential-broker grant/1", "swarma-credential-broker revocation/1"}


def split_tag(raw, malformed):
    tag, delimiter, payload = raw.partition(b"\n")
    require(delimiter and 1 <= len(tag) <= 96 and all(0x20 <= c <= 0x7e for c in tag), malformed)
    return tag, payload


def signer_admission(raw, f):
    require(len(raw) <= 24576, "signer_preimage_too_large")
    tag, payload = split_tag(raw, "signer_tag_malformed")
    require(tag == b"swarma-msg/2", "signer_domain_refused")
    try:
        decoded = parse(payload, max_depth=12)
        canonical = ccj(decoded)
    except Refusal:
        raise Refusal("signer_payload_invalid") from None
    require(canonical == payload, "signer_payload_invalid")
    enabled, multi_agent = f.get("identity_check", False), f.get("multi_agent", False)
    require(type(enabled) is bool and type(multi_agent) is bool, "signer_identity_unavailable")
    if enabled or multi_agent:
        caller_key = f.get("caller_key_id")
        try:
            alg, public = key_bytes(caller_key)
            require(alg == "ed25519", "envelope_malformed")
            point(public)
        except Refusal:
            raise Refusal("signer_identity_unavailable") from None
        caller_attestation = f.get("caller_attestation_id")
        try:
            hash_id(caller_attestation)
        except Refusal:
            raise Refusal("signer_identity_unavailable") from None
        # These exact paths are each read once after duplicate-free CCJ admission.
        require(type(decoded) is dict, "signer_identity_malformed")
        key = decoded.get("key")
        body = decoded.get("body")
        require(type(body) is dict, "signer_identity_malformed")
        author = body.get("author")
        author_attestation = body.get("author_attestation")
        require(type(key) is str and type(author) is str and type(author_attestation) is str, "signer_identity_malformed")
        require(key == caller_key and author == caller_key and author_attestation == caller_attestation, "signer_identity_mismatch")
    return {"tag": "swarma-msg/2", "preimage_sha256": digest(raw)}


def check_domain(inp, f):
    expected = f.get("expected_tag")
    require(type(expected) is str and expected in REGISTERED_TAGS, "domain_unknown")
    raw = unb64(inp["preimage"])
    tag, payload = split_tag(raw, "domain_tag_malformed")
    require(tag == expected.encode("ascii"), "domain_mismatch")
    require(ccj(parse(payload)) == payload, "envelope_malformed")
    verify_signature(inp["key"], unb64(inp["sig"], 64), raw)
    return {"tag": expected, "key": inp["key"]}


def signing_preimage(body, key, role, expected):
    return (OWN_TAGS[expected]+"\n").encode("ascii") + ccj({
        "version": "swarm-envelope/2", "role": role, "key": key, "body": body})


def evidence_object(value, names=()):
    # Availability precedes type/semantic equality; None never stands for a tuple.
    require(value is not None, "key_binding_unavailable")
    require(type(value) is dict, "key_binding_invalid")
    require(all(n in value and value[n] is not None for n in names), "key_binding_unavailable")
    return value


def bounded_text(value, code="key_binding_invalid"):
    require(type(value) is str and not any(0xD800 <= ord(c) <= 0xDFFF for c in value)
            and 1 <= len(value.encode("utf-8")) <= 255, code)
    return value


def principal_tuple(value):
    names = ("owner", "path", "generation", "registration_number", "master_epoch", "uid")
    value = evidence_object(value, names)
    require(set(value) <= set(names) | {"active"}, "key_binding_invalid")
    for name in ("owner", "path", "generation", "master_epoch"):
        bounded_text(value[name])
    number, uid = value["registration_number"], value["uid"]
    require(type(number) is int and 1 <= number <= 9007199254740991
            and type(uid) is int and 0 <= uid <= 4294967294, "key_binding_invalid")
    return tuple(value[n] for n in names)


def evidence_exact(value, names):
    value = evidence_object(value, names.split())
    require(set(value) == set(names.split()), "key_binding_invalid")
    return value


def signed_evidence(value, expected, root):
    require(value is not None, "key_binding_unavailable")
    require(type(value) is str, "key_binding_invalid")
    try:
        raw = unb64(value)
        require(len(raw) <= 8192, "key_binding_invalid")
        e = parse(raw)
    except Refusal:
        raise Refusal("key_binding_invalid") from None
    evidence_exact(e, "version body id signatures")
    b = evidence_object(e["body"], ("type", "issuer"))
    require(type(e["signatures"]) is list and len(e["signatures"]) == 1, "key_binding_invalid")
    sig = evidence_exact(e["signatures"][0], "role key sig")
    try:
        for identity in (root, b["issuer"], sig["key"]):
            key_bytes(identity)
        hash_id(e["id"])
        require(e["version"] == "swarm-envelope/2" and b.get("type") == expected
                and b["issuer"] == root and sig["key"] == root and sig["role"] == "author", "key_binding_invalid")
        require(e["id"] == digest((OWN_TAGS[expected]+"\n").encode("ascii")+ccj(b)), "key_binding_invalid")
        verify_signature(root, unb64(sig["sig"], 64), signing_preimage(b, root, "author", expected))
    except Refusal:
        raise Refusal("key_binding_invalid") from None
    return e


def root_role_separation(f):
    # Compare present protected pins before consuming any signed evidence.
    # Missing/malformed policy retains its purpose-specific availability checks.
    service, registry = f.get("service_root"), f.get("agent_revocation_root")
    pins = [service.get("key") if type(service) is dict else None,
            registry.get("key") if type(registry) is dict else None,
            f.get("operator_root"), f.get("root"), f.get("commit_signing_key"), f.get("enrollment_publisher")]
    present = [pin for pin in pins if type(pin) is str]
    require(len(present) == len(set(present)), "key_binding_invalid")

    services = f.get("service_attestations")
    agents, devices = f.get("active_generations"), f.get("operator_attestations")
    for k in services if type(services) is dict else {}:
        require(k not in present and not (type(agents) is dict and k in agents)
                and not (type(devices) is dict and k in devices), "key_binding_invalid")
    for role in ("commit_signing_key", "enrollment_publisher"):
        if role in f:
            try:
                key_bytes(f[role])
            except Refusal:
                raise Refusal("key_binding_invalid") from None
            require(not (type(agents) is dict and f[role] in agents)
                    and not (type(devices) is dict and f[role] in devices), "key_binding_invalid")


def snapshot_header(f, root):
    root_role_separation(f)
    records = evidence_object(f.get("revocations"))
    record = evidence_object(records.get(root), ("availability", "max_age", "rollback_safe", "snapshot"))
    require(type(record["availability"]) is str, "key_binding_invalid")
    require(record["availability"] != "unavailable", "key_binding_unavailable")
    require(record["availability"] == "available", "key_binding_invalid")
    require(type(record["max_age"]) is int and 0 < record["max_age"] <= 60
            and type(record["rollback_safe"]) is bool, "key_binding_invalid")
    b = signed_evidence(record["snapshot"], "revocation/1", root)["body"]
    evidence_exact(b, "type issuer issued_at complete entries")
    require(type(b["complete"]) is bool and type(b["entries"]) is list, "key_binding_invalid")
    try:
        issued = timestamp(b["issued_at"])
    except Refusal:
        raise Refusal("key_binding_invalid") from None
    low, high = time_values(f)
    receipt_gate(f, low, high)
    require(b["complete"] and record["rollback_safe"] and issued <= low, "key_binding_unavailable")
    return b, issued, high, record["max_age"]


def snapshot_entries(b, high, ids, keys):
    effective_entries = []
    for entry in b["entries"]:
        evidence_exact(entry, "kind id from")
        require(type(entry["kind"]) is str and entry["kind"] in {"key", "record"}, "key_binding_invalid")
        try:
            when = timestamp(entry["from"])
            if entry["kind"] == "key":
                key_bytes(entry["id"])
            else:
                hash_id(entry["id"])
        except Refusal:
            raise Refusal("key_binding_invalid") from None
        effective_entries.append((entry["kind"], entry["id"], when))
    # Validate the complete snapshot before matching; current time, never old iat.
    require(not any(when <= high and item in (keys if kind == "key" else ids)
                    for kind, item, when in effective_entries), "revoked")


def signed_snapshot(f, root, ids, keys):
    b, issued, high, max_age = snapshot_header(f, root)
    if not receipt_snapshot(f, root, b):
        require(high-issued <= max_age, "key_binding_unavailable")
    snapshot_entries(b, high, ids, keys)
    return b


def snapshot_base(f, root):
    b, issued, high, max_age = snapshot_header(f, root)
    snapshot_entries(b, high, [], [])
    return b, max_age


def verify_attestation(key, f, device=False, check_revocation=True, reference=None, direct=False):
    root_role_separation(f)
    message_reference = reference is not None and not direct
    collection = "operator_attestations" if device else "attestations"
    records = evidence_object(f.get(collection))
    lookup = key
    if not device:
        if reference is None:
            current_ids = evidence_object(f.get("agent_attestation_ids"))
            reference = current_ids.get(key)
        require(reference is not None, "key_binding_unavailable")
        try:
            hash_id(reference)
        except Refusal:
            raise Refusal("key_binding_invalid") from None
        lookup = reference
    require(lookup in records, "key_binding_unavailable")
    if device:
        root = f.get("operator_root")
        require(root is not None, "key_binding_unavailable")
    else:
        root_record = evidence_exact(f.get("service_root"), "key purpose")
        require(type(root_record["purpose"]) is int and root_record["purpose"] == 5, "key_binding_invalid")
        root = root_record["key"]
    e = signed_evidence(records[lookup], "attestation/1", root)
    b = evidence_exact(e["body"], "type issuer subject key_class purpose roles actions iat exp binding")
    subject = evidence_exact(b["subject"], "algorithm key_id public_bytes")
    require(all(type(subject[n]) is str for n in subject)
            and all(type(b[n]) is str for n in ("key_class", "purpose", "iat", "exp"))
            and type(b["roles"]) is list and type(b["actions"]) is list, "key_binding_invalid")
    requested_key = key
    if not device and message_reference:
        key = subject["key_id"]
    try:
        alg, public = key_bytes(key)
        subject_alg, subject_public = key_bytes(subject["key_id"])
        encoded = unb64(subject["public_bytes"], 33 if device else 32)
        start, end = timestamp(b["iat"]), timestamp(b["exp"])
    except Refusal:
        raise Refusal("key_binding_invalid") from None
    try:
        if alg == "ed25519":
            point(public)
        else:
            require(ec is not None, "PENDING_p256_cryptography_unavailable")
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
    except (Refusal, ValueError):
        raise Refusal("key_binding_invalid") from None
    require(subject_alg == alg and subject_public == public
            and subject["key_id"] == key and encoded == public and 0 < end-start
            and (device or end-start <= 86400), "key_binding_invalid")
    if device:
        require(alg == "p256" and subject["algorithm"] == "P-256"
                and b["key_class"] == "operator-device" and b["purpose"] == "operator-device"
                and b["roles"] == ["act", "approver"]
                and b["actions"] == ["act.sign", "grant.sign", "message.approve"], "key_binding_invalid")
        # Protected availability/type precedes either owner's bound and equality.
        owner = f.get("operator_owner")
        require(owner is not None, "key_binding_unavailable")
        require(type(owner) is str, "key_binding_invalid")
        bounded_text(owner)
        binding = evidence_exact(b["binding"], "owner")
        bounded_text(binding["owner"])
        require(binding["owner"] == owner, "key_binding_invalid")
    else:
        require(alg == "ed25519" and subject["algorithm"] == "Ed25519"
                and b["key_class"] == "agent" and b["purpose"] == "swarma-msg"
                and b["roles"] == ["author"] and b["actions"] == ["message.sign"], "key_binding_invalid")
        current = evidence_object(f.get("active_generations"))
        require(key in current, "key_binding_unavailable")
        current_binding = evidence_object(current[key], ("active",))
        left, right = principal_tuple(b["binding"]), principal_tuple(current_binding)
        require(set(b["binding"]) == {"owner", "path", "generation", "registration_number", "master_epoch", "uid"}, "key_binding_invalid")
        require(type(current_binding["active"]) is bool and current_binding["active"]
                and left == right, "key_binding_invalid")
    low, high = time_values(f)
    receipt_gate(f, low, high)
    require(start <= low and high < end, "key_binding_invalid")
    if check_revocation:
        revoker = root
        if not device:
            policy = evidence_exact(f.get("agent_revocation_root"), "key purpose attestation_root")
            require(policy["purpose"] == "registry-revocation" and policy["attestation_root"] == root
                    and policy["key"] != root, "key_binding_invalid")
            try:
                key_bytes(policy["key"])
            except Refusal:
                raise Refusal("key_binding_invalid") from None
            revoker = policy["key"]
        signed_snapshot(f, revoker, [e["id"]], [key])
    if not device and not message_reference:
        require(e["id"] == reference and key == requested_key, "key_binding_invalid")
    return e


def agent_binding(key, f, reference=None):
    return verify_attestation(key, f, reference=reference)


def grant_root(f):
    root = f.get("root")
    require(root is not None, "key_binding_unavailable")
    try:
        key_bytes(root)
    except Refusal:
        raise Refusal("key_binding_invalid") from None
    return root


def protocol_signer_excluded(key, expected, f):
    if key in (f.get("commit_signing_key"), f.get("enrollment_publisher")):
        return True
    services = f.get("service_attestations")
    return type(services) is dict and key in services and expected != "grant/1"


def service_identity(key, f):
    root_role_separation(f)
    policy = evidence_exact(f.get("service_authority"), "key purpose owner")
    require(policy["key"] == grant_root(f) and policy["purpose"] == "grant-service", "key_binding_invalid")
    owner = bounded_text(policy["owner"])
    services = evidence_object(f.get("service_attestations"))
    e = signed_evidence(services.get(key), "attestation/1", policy["key"])
    b = evidence_exact(e["body"], "type issuer subject key_class purpose roles actions iat exp binding")
    subject = evidence_exact(b["subject"], "algorithm key_id public_bytes")
    try:
        algorithm, public = key_bytes(key)
        require(algorithm == "ed25519", "key_binding_invalid")
        point(public)
        encoded = unb64(subject["public_bytes"], 32)
        start, end = timestamp(b["iat"]), timestamp(b["exp"])
    except Refusal:
        raise Refusal("key_binding_invalid") from None
    binding = evidence_exact(b["binding"], "owner")
    require(bounded_text(binding["owner"]) == owner, "key_binding_invalid")
    require(subject["algorithm"] == "Ed25519" and subject["key_id"] == key and encoded == public
            and b["key_class"] == "service" and b["purpose"] == "grant-service"
            and b["roles"] == ["author"] and b["actions"] == ["grant.sign"], "key_binding_invalid")
    low, high = time_values(f)
    receipt_gate(f, low, high)
    require(0 < end-start <= 86400 and start <= low and high < end, "key_binding_invalid")
    signed_snapshot(f, policy["key"], [e["id"]], [key])
    return e


def grant_key_binding(key, f, issuer=False):
    # Protected authority-root provenance is independent of algorithm/position.
    if key == grant_root(f):
        return
    services = f.get("service_attestations")
    if type(services) is dict and key in services:
        service_identity(key, f)
        return
    devices = evidence_object(f.get("operator_attestations"))
    if key in devices:
        verify_attestation(key, f, device=True)
        operator_key_current(f)
    else:
        agent_binding(key, f)
        require(not issuer, "signature_profile_invalid")


def delivery_binding(b, f):
    d = f.get("delivery")
    require(type(d) is dict and all(type(d.get(n)) is str and re.fullmatch(r"[!-~]{1,255}", d[n])
                                    for n in ("room", "to")), "message_context_unavailable")
    require(b["room"] == d["room"], "message_room_mismatch")
    require(b["to"] == d["to"], "message_recipient_mismatch")
    require(d.get("text") is not None, "message_text_unavailable")
    try:
        text = unb64(d["text"])
        text.decode("utf-8")
    except (Refusal, UnicodeError):
        raise Refusal("message_text_invalid") from None
    require(hashlib.sha256(text).hexdigest() == b["body_sha256"], "message_text_mismatch")


def assurance_value(value, code):
    require(type(value) is dict and set(value) == {"level", "presence"}, code)
    require(type(value["level"]) is str and value["level"] in {"A1", "A2", "A3"}
            and type(value["presence"]) is bool, code)
    return int(value["level"][1]), value["presence"]


def envelope(raw, expected, f):
    require(len(raw) <= (8192 if expected == "operator-act/1" else 65536), "envelope_too_large")
    e = parse(raw)
    schema(e, expected)
    require(e["version"] == "swarm-envelope/2", "envelope_version_unsupported")
    b, sigs = e["body"], e["signatures"]
    require(b["type"] == expected, "envelope_type_mismatch")
    pairs_seen = [(s["role"], s["key"]) for s in sigs]
    roles = []
    if expected != "grant/1":
        roles = f.get("required_roles")
        require(roles is not None, "signer_unavailable")
        require(type(roles) is list and all(type(role) is str and role in {"author", "approver", "delegate"}
                                          for role in roles), "envelope_role_invalid")
    required = (["author"] + roles if expected == "message/1"
                else ["author"] if expected == "grant/1" else ["approver"] + roles)
    require(all(s["role"] in {"author", "approver", "delegate"} for s in sigs)
            and len(set(pairs_seen)) == len(sigs)
            and set(required) <= {s["role"] for s in sigs}, "envelope_role_invalid")
    if expected in {"grant/1", "operator-act/1"}:
        require(len(sigs) == 1 and sigs[0]["role"] == ("author" if expected == "grant/1" else "approver"), "envelope_role_invalid")
    require(e["id"] == digest((OWN_TAGS[expected] + "\n").encode("ascii")+ccj(b)), "envelope_id_mismatch")
    for s in sigs:
        if expected == "grant/1":
            require(s["key"] == b["issuer"], "signer_unknown")
        elif expected == "message/1" and s["role"] == "author":
            known = f.get("known_keys")
            require(known is not None, "signer_unavailable")
            require(type(known) is list and all(type(key) is str for key in known), "signer_unknown")
            require(s["key"] in known and s["key"] == b["author"], "signer_unknown")
        alg, _ = key_bytes(s["key"])
        allowed = ((expected == "message/1" and (s["role"], alg) in {("author", "ed25519"), ("approver", "p256")})
                   or (expected == "operator-act/1" and (s["role"], alg) == ("approver", "p256"))
                   or (expected == "grant/1" and s["role"] == "author" and alg in {"ed25519", "p256"}))
        service_root = f.get("service_root")
        if type(service_root) is dict:
            require(s["key"] != service_root.get("key"), "signature_profile_invalid")
        require(allowed and not protocol_signer_excluded(s["key"], expected, f), "signature_profile_invalid")
        pre = signing_preimage(b, s["key"], s["role"], expected)
        if expected == "message/1":
            require(len(pre) <= 24576, "signature_preimage_too_large")
            try:
                values({"version": "swarm-envelope/2", "role": s["role"], "key": s["key"], "body": b}, max_depth=12)
            except Refusal:
                raise Refusal("signature_preimage_invalid") from None
        # E6 admits issuer and profile before checking any subject point.
        if expected == "grant/1":
            alg, public = key_bytes(b["subject"])
            if alg == "ed25519":
                point(public)
            else:
                require(ec is not None, "PENDING_p256_cryptography_unavailable")
                try:
                    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
                except ValueError:
                    raise Refusal("envelope_signature_invalid") from None
        verify_signature(s["key"], unb64(s["sig"], 64), pre)
    audience = f.get("audience")
    require(type(audience) is str and re.fullmatch(r"[!-~]{1,255}", audience), "audience_mismatch")
    require(b["aud"] == audience, "audience_mismatch")
    if expected == "message/1":
        delivery_binding(b, f)
    low, high = time_values(f)
    receipt_gate(f, low, high)
    window(b["iat"], b["exp"], low, high)
    if expected == "message/1":
        author = agent_binding(b["author"], f, reference=b["author_attestation"])
        if any(s["role"] == "approver" for s in sigs):
            operator_key_current(f)
            for sig in sigs:
                if sig["role"] == "approver":
                    verify_attestation(sig["key"], f, device=True)
        require(author["id"] == b["author_attestation"]
                and author["body"]["subject"]["key_id"] == b["author"], "author_attestation_mismatch")

    elif expected == "grant/1":
        grant_key_binding(b["issuer"], f, issuer=True)
        grant_key_binding(b["subject"], f)
    require(f.get("id_journal_available") is True, "id_journal_unavailable")
    seen = f.get("seen")
    require(type(seen) is dict, "id_journal_unavailable")
    require(e["id"] not in seen or unb64(seen[e["id"]]) == raw, "envelope_conflict")
    return e


def contains(parent, child):
    if parent["kind"] != child["kind"]:
        return False
    if parent["kind"] == "credential" and any(parent[k] != child[k] for k in ("harness", "profile")):
        return False
    p, c = parent["id"], child["id"]
    if not p.endswith("/*"):
        return c == p
    p = p[:-2]
    if c.endswith("/*"):
        c = c[:-2]
        return c == p or c.startswith(p + "/")
    return c.startswith(p + "/")


def effective(b):
    c = b["caveats"]
    return (timestamp(c["not_before"]), timestamp(c["expires"])) if c else (timestamp(b["iat"]), timestamp(b["exp"]))


def revocation(f, ids, keys, root=None):
    try:
        signed_snapshot(f, grant_root(f) if root is None else root, ids, keys)
    except Refusal as error:
        if str(error) == "key_binding_unavailable":
            raise Refusal("revocation_unavailable") from None
        if str(error) == "key_binding_invalid":
            raise Refusal("revocation_invalid") from None
        raise


def grants(raw_chain, f):
    require(type(raw_chain) is list and 1 <= len(raw_chain) <= 4, "grant_chain_malformed")
    raw = [unb64(r) for r in raw_chain]
    require(sum(map(len, raw)) <= 262144, "grant_chain_malformed")
    # G1 duplicate IDs require only bounded lexical parse, before envelope crypto.
    ids = [parse(r).get("id") if isinstance(parse(r), dict) else None for r in raw]
    require(all(isinstance(i, str) for i in ids) and len(set(ids)) == len(ids), "grant_chain_malformed")
    req = f.get("request")
    require(isinstance(req, dict) and set(req) == {"key", "action", "target"}, "grant_chain_malformed")
    # G1 checks request field types before later set/dict/containment operations.
    try:
        key_bytes(req["key"])
        require(isinstance(req["action"], str), "envelope_malformed")
        t = req["target"]
        require(isinstance(t, dict) and isinstance(t.get("kind"), str), "envelope_malformed")
        exact(t, "kind id harness profile" if t["kind"] == "credential" else "kind id")
        require(all(isinstance(v, str) for v in t.values()), "envelope_malformed")
    except Refusal:
        raise Refusal("grant_chain_malformed") from None
    es = [envelope(r, "grant/1", f) for r in raw]
    bs = [e["body"] for e in es]
    for child, parent, pe in zip(bs, bs[1:], es[1:]):
        require(child["parent"] == pe["id"] and child["issuer"] == parent["subject"], "grant_chain_broken")
    require(bs[-1]["parent"] is None and bs[-1]["issuer"] == grant_root(f), "grant_root_unknown")
    for child, parent in zip(bs, bs[1:]):
        cs, ce = effective(child)
        ps, pe = effective(parent)
        require(child["depth"] < parent["depth"] and set(child["actions"]) <= set(parent["actions"])
                and all(any(contains(p, c) for p in parent["targets"]) for c in child["targets"])
                and timestamp(child["iat"]) >= timestamp(parent["iat"])
                and timestamp(child["exp"]) <= timestamp(parent["exp"])
                and cs >= ps and ce <= pe and child["aud"] == parent["aud"]
                and assurance_value(child["min_assurance"], "envelope_malformed")[0] >= assurance_value(parent["min_assurance"], "envelope_malformed")[0]
                and (not parent["min_assurance"]["presence"] or child["min_assurance"]["presence"]), "grant_not_narrowing")
    vocabulary = {"credential.lease": "credential", "agent.spawn": "station", "message.deliver": "station"}
    for b in bs:
        require(set(b["actions"]) <= vocabulary.keys(), "action_unregistered")
        kinds = {vocabulary[a] for a in b["actions"]}
        require(kinds == {t["kind"] for t in b["targets"]}, "grant_target_invalid")
    low, high = time_values(f)
    for b in bs:
        start, end = effective(b)
        require(high < end, "expired")
        require(low >= start, "not_yet_valid")
    revocation(f, ids, [b[k] for b in bs for k in ("issuer", "subject")])
    require(target(req["target"]), "request_target_invalid")
    require(req["action"] in vocabulary, "action_unregistered")
    leaf = bs[0]
    require(req["key"] == leaf["subject"] and req["action"] in leaf["actions"]
            and vocabulary[req["action"]] == req["target"]["kind"]
            and any(contains(t, req["target"]) for t in leaf["targets"]), "grant_not_authorized")
    minimum, presence = assurance_value(leaf["min_assurance"], "envelope_malformed")
    established, present = assurance_value(f.get("assurance"), "grant_assurance_unavailable")
    require(established < 3, "grant_assurance_unavailable")
    require(established >= minimum and (not presence or present), "grant_assurance_insufficient")
    return es


def operator_key_current(f):
    facts = evidence_object(f.get("signer_facts"))
    current = facts.get("current")
    require(type(current) is bool, "key_binding_unavailable")
    require(current, "key_binding_invalid")


def operator(e, f):
    b = e["body"]
    operations = {"revoke": ("registration", False), "grant.issue": ("account", True)}
    require(b["operation"] in operations, "act_operation_unknown")
    kind, widening = operations[b["operation"]]
    binding = f.get("binding")
    require(type(binding) is dict and all(n in binding for n in ("operation", "target", "owner", "epoch", "arguments")), "act_binding_mismatch")
    bounded_text(binding["owner"], "act_binding_mismatch")
    require(type(binding["epoch"]) is str and re.fullmatch(r"[!-~]{1,255}", binding["epoch"])
            and type(binding["operation"]) is str and identifier(binding["operation"].replace(".", "/"))
            and target(binding["target"], operator=True) and type(binding["arguments"]) is dict, "act_binding_mismatch")
    require(b["operation"] == binding["operation"] and b["target"] == binding["target"]
            and b["target"]["kind"] == kind and b["owner"] == binding["owner"]
            and b["epoch"] == binding["epoch"]
            and b["arguments_digest"] == digest(ccj(binding["arguments"])), "act_binding_mismatch")
    root_role_separation(f)
    operator_key_current(f)
    attestation = verify_attestation(e["signatures"][0]["key"], f, device=True, check_revocation=False)
    require(attestation["body"]["binding"]["owner"] == b["owner"], "key_binding_invalid")
    revocation(f, [e["id"], attestation["id"]], [s["key"] for s in e["signatures"]], root=f["operator_root"])
    if widening:
        require(b["confirmed"], "act_confirmation_required")
        require(f["signer_facts"].get("presence") is True and f["signer_facts"].get("presence_current") is True, "act_presence_required")
    require(f.get("replay_available") is True, "replay_unavailable")
    used = f.get("used_actions")
    require(type(used) is list and all(type(action) is str for action in used), "replay_unavailable")
    require(b["action_id"] not in used, "act_replay")
    if widening:
        raise Refusal("act_a3_inactive")


def journal_wire(raw, checkpoint):
    try:
        require(len(raw) <= 8192, "journal_malformed")
        e = parse(raw)
        names = "version body id signatures" if checkpoint else "version body id"
        evidence_exact(e, names)
        require(type(e["version"]) is str, "journal_malformed")
        hash_id(e["id"])
        b = e["body"]
        body_names = "type registry owner seq at " + ("head snapshot" if checkpoint else "prev op record_type record")
        require(type(b) is dict and set(b) == set(body_names.split()), "journal_malformed")
        require(type(b["type"]) is str and type(b["seq"]) is int
                and 1 <= b["seq"] <= 9007199254740991, "journal_malformed")
        key_bytes(b["registry"])
        bounded_text(b["owner"])
        timestamp(b["at"])
        if checkpoint:
            hash_id(b["head"])
            hash_id(b["snapshot"])
            require(type(e["signatures"]) is list and 1 <= len(e["signatures"]) <= 8, "journal_malformed")
            for s in e["signatures"]:
                evidence_exact(s, "role key sig")
                require(type(s["role"]) is str, "journal_malformed")
                key_bytes(s["key"])
                unb64(s["sig"], 64)
        else:
            require((b["seq"] == 1) == (b["prev"] is None), "journal_malformed")
            if b["prev"] is not None:
                hash_id(b["prev"])
            require(type(b["op"]) is str and b["op"] in {"add", "revoke"}
                    and type(b["record_type"]) is str
                    and b["record_type"] in {"attestation/1", "grant/1", "revocation/1", "enrollment/1"}, "journal_malformed")
            hash_id(b["record"])
        return e
    except Refusal:
        raise Refusal("journal_malformed") from None


def journal_policy(f):
    try:
        require(f.get("registry_owner") is not None, "key_binding_unavailable")
        owner = bounded_text(f["registry_owner"])
        registry = evidence_exact(f.get("agent_revocation_root"), "key purpose attestation_root")
        service = evidence_exact(f.get("service_root"), "key purpose")
        root_role_separation(f)
        require(type(service["purpose"]) is int and service["purpose"] == 5
                and registry["purpose"] == "registry-revocation"
                and registry["attestation_root"] == service["key"], "key_binding_invalid")
        key_bytes(service["key"])
        key_bytes(registry["key"])
        return registry["key"], owner
    except Refusal as error:
        raise Refusal("journal_unavailable" if str(error) == "key_binding_unavailable" else "journal_invalid") from None


def checkpoint_signature(e, root, owner):
    b = e["body"]
    try:
        require(len(e["signatures"]) == 1, "checkpoint_invalid")
        s = e["signatures"][0]
        require(e["version"] == "swarm-envelope/2" and b["type"] == "checkpoint/1"
                and b["registry"] == root and b["owner"] == owner
                and s["key"] == root and s["role"] == "author", "checkpoint_invalid")
        require(e["id"] == digest((OWN_TAGS["checkpoint/1"]+"\n").encode("ascii")+ccj(b)), "checkpoint_invalid")
        verify_signature(root, unb64(s["sig"], 64), signing_preimage(b, root, "author", "checkpoint/1"))
    except Refusal:
        raise Refusal("checkpoint_invalid") from None


def current_checkpoint(e, root, owner, f):
    checkpoint_signature(e, root, owner)
    b = e["body"]
    low, high = time_values(f)
    at = timestamp(b["at"])
    require(at <= low and high-at <= 60, "journal_unavailable")
    try:
        snapshot = signed_snapshot(f, root, [], [])
    except Refusal as error:
        if str(error) in {"time_unavailable", "watermark_unavailable"}:
            raise
        raise Refusal("journal_unavailable" if str(error) == "key_binding_unavailable" else "checkpoint_snapshot_invalid") from None
    snapshot_id = digest((OWN_TAGS["revocation/1"]+"\n").encode("ascii")+ccj(snapshot))
    require(b["snapshot"] == snapshot_id, "checkpoint_snapshot_invalid")
    require(timestamp(snapshot["issued_at"]) <= at
            and high-at <= f["revocations"][root]["max_age"], "journal_unavailable")


def journal_witness(f, root, owner):
    require(f.get("journal_witness") is not None, "journal_unavailable")
    try:
        w = f["journal_witness"]
        require(type(w) is dict and set(w) == {"registry_id", "owner", "registry_seq", "registry_head", "checkpoint_id", "previous_checkpoint_id"}, "journal_witness_invalid")
        require(w["registry_id"] == root and w["owner"] == owner and type(w["registry_seq"]) is int
                and 1 <= w["registry_seq"] <= 9007199254740991, "journal_witness_invalid")
        hash_id(w["registry_head"])
        hash_id(w["checkpoint_id"])
        if w["previous_checkpoint_id"] is not None:
            hash_id(w["previous_checkpoint_id"])
            require(w["previous_checkpoint_id"] != w["checkpoint_id"], "journal_witness_invalid")
        return w
    except Refusal:
        raise Refusal("journal_witness_invalid") from None


def prior_checkpoint(f, w, root, owner):
    require(f.get("id_journal_available") is True and f.get("seen") is not None, "journal_unavailable")
    require(type(f["seen"]) is dict, "checkpoint_invalid")
    value = f["seen"].get(w["checkpoint_id"])
    require(value is not None, "journal_unavailable")
    try:
        prior = journal_wire(unb64(value), True)
        checkpoint_signature(prior, root, owner)
        require(prior["id"] == w["checkpoint_id"]
                and prior["body"]["seq"] == w["registry_seq"]
                and prior["body"]["head"] == w["registry_head"], "checkpoint_invalid")
        return prior
    except Refusal:
        raise Refusal("checkpoint_invalid") from None


def identity_journal(inp, f):
    # J1 parses the entire bounded suffix and both checkpoint structures before
    # J2 policy; J3 authenticates both before J4 witness/J5 fork comparison.
    require(type(inp["entries"]) is list and len(inp["entries"]) <= 64, "journal_malformed")
    try:
        raws = [unb64(value) for value in inp["entries"]]
        raw_cp = unb64(inp["checkpoint"])
        conflict = unb64(inp["conflict"]) if "conflict" in inp else b""
        require(sum(map(len, raws)) + len(raw_cp) + len(conflict) <= 540672, "journal_malformed")
    except Refusal:
        raise Refusal("journal_malformed") from None
    currency_version(raw_cp, "checkpoint/1")
    if conflict: currency_version(conflict, "checkpoint/1")
    entries = [journal_wire(raw, False) for raw in raws]
    cp = journal_wire(raw_cp, True)
    other = journal_wire(conflict, True) if conflict else None
    root, owner = journal_policy(f)
    current_checkpoint(cp, root, owner, f)
    if other is not None:
        current_checkpoint(other, root, owner, f)
    w = journal_witness(f, root, owner)
    b = cp["body"]
    if other is not None:
        require(other["body"]["seq"] != b["seq"] or (other["body"]["head"] == b["head"] and other["id"] == cp["id"]), "journal_fork")
    require(w["registry_seq"] != b["seq"] or (w["registry_head"] == b["head"] and w["checkpoint_id"] == cp["id"]), "journal_fork")
    require(b["seq"] >= w["registry_seq"], "journal_rollback")
    if b["seq"] > w["registry_seq"]:
        prior = prior_checkpoint(f, w, root, owner)
        require(timestamp(b["at"]) >= timestamp(prior["body"]["at"]), "journal_rollback")
        require(bool(entries) and entries[0]["body"]["seq"] == w["registry_seq"]
                and entries[0]["id"] == w["registry_head"], "journal_anchor_required")
    seq, head, at = w["registry_seq"], w["registry_head"], 0
    for index, e in enumerate(entries):
        entry = e["body"]
        require(e["version"] == "swarm-envelope/2" and entry["type"] == "journal-entry/1"
                and entry["registry"] == root and entry["owner"] == owner
                and e["id"] == digest((OWN_TAGS["journal-entry/1"]+"\n").encode("ascii")+ccj(entry)), "journal_entry_invalid")
        when = timestamp(entry["at"])
        if index == 0 and entry["seq"] == seq:
            require(e["id"] == head and when <= timestamp(b["at"]), "journal_chain_broken")
            at = when
            continue
        require(entry["seq"] == seq+1 and entry["prev"] == head and at <= when <= timestamp(b["at"]), "journal_chain_broken")
        seq, head, at = entry["seq"], e["id"], when
    require(seq == b["seq"] and head == b["head"], "journal_chain_broken")
    return [cp]


def freshness_wire(raw):
    try:
        require(len(raw) <= 8192, "freshness_malformed")
        e = parse(raw)
        require(type(e) is dict and set(e) == {"version", "body", "id", "signatures"}, "freshness_malformed")
        require(type(e["version"]) is str, "freshness_malformed")
        hash_id(e["id"])
        b = e["body"]
        require(type(b) is dict and set(b) == {"type", "registry", "owner", "publication_seq", "prev", "issued_at", "snapshot", "registry_seq", "checkpoint_id"}, "freshness_malformed")
        require(type(b["type"]) is str, "freshness_malformed")
        key_bytes(b["registry"])
        bounded_text(b["owner"])
        for field in ("publication_seq", "registry_seq"):
            require(type(b[field]) is int and 1 <= b[field] <= 9007199254740991, "freshness_malformed")
        require(b["publication_seq"] != 1 or b["prev"] is None, "freshness_malformed")
        if b["prev"] is not None:
            hash_id(b["prev"])
        timestamp(b["issued_at"])
        hash_id(b["snapshot"])
        hash_id(b["checkpoint_id"])
        require(type(e["signatures"]) is list and 1 <= len(e["signatures"]) <= 8, "freshness_malformed")
        for sig in e["signatures"]:
            require(type(sig) is dict and set(sig) == {"role", "key", "sig"}, "freshness_malformed")
            require(type(sig["role"]) is str, "freshness_malformed")
            key_bytes(sig["key"])
            unb64(sig["sig"], 64)
        return e
    except Refusal:
        raise Refusal("freshness_malformed") from None


def freshness_signature(e, root, owner):
    try:
        b = e["body"]
        require(len(e["signatures"]) == 1, "freshness_signature_invalid")
        sig = e["signatures"][0]
        require(e["version"] == "swarm-envelope/2" and b["type"] == "freshness/1"
                and b["registry"] == root and b["owner"] == owner
                and sig["key"] == root and sig["role"] == "author", "freshness_signature_invalid")
        require(e["id"] == digest((OWN_TAGS["freshness/1"]+"\n").encode("ascii")+ccj(b)), "freshness_signature_invalid")
        verify_signature(root, unb64(sig["sig"], 64), signing_preimage(b, root, "author", "freshness/1"))
    except Refusal:
        raise Refusal("freshness_signature_invalid") from None


def publication_anchor(f, root, owner):
    require(f.get("freshness_anchor") is not None, "freshness_unavailable")
    try:
        a = f["freshness_anchor"]
        require(type(a) is dict and set(a) == {"registry_id", "owner", "publication_seq", "freshness_id", "issued_at", "snapshot", "registry_seq", "checkpoint_id"}, "freshness_state_invalid")
        require(a["registry_id"] == root and a["owner"] == owner
                and type(a["publication_seq"]) is int and 0 <= a["publication_seq"] <= 9007199254740991
                and type(a["registry_seq"]) is int and 1 <= a["registry_seq"] <= 9007199254740991, "freshness_state_invalid")
        hash_id(a["snapshot"])
        hash_id(a["checkpoint_id"])
        if a["publication_seq"] == 0:
            require(a["freshness_id"] is None and a["issued_at"] is None, "freshness_state_invalid")
        else:
            hash_id(a["freshness_id"])
            timestamp(a["issued_at"])
        return a
    except Refusal:
        raise Refusal("freshness_state_invalid") from None


def fresh_revocation(inp, f, reanchor=False):
    # Parse every proof record and current checkpoint before policy or crypto.
    require(type(inp["chain"]) is list, "freshness_malformed")
    require(bool(inp["chain"]), "freshness_unavailable")
    require(len(inp["chain"]) <= 64 and (not reanchor or len(inp["chain"]) == 1), "freshness_malformed")
    try:
        raws = [unb64(value) for value in inp["chain"]]
        checkpoint_raw = unb64(inp["checkpoint"])
        require(sum(map(len, raws))+len(checkpoint_raw) <= 532480, "freshness_malformed")
        for raw in raws: currency_version(raw, "freshness/1")
        currency_version(checkpoint_raw, "checkpoint/1")
        proof = [freshness_wire(raw) for raw in raws]
        cp = journal_wire(checkpoint_raw, True)
    except Refusal as error:
        if str(error) == "registry_currency_version_mismatch": raise
        raise Refusal("freshness_malformed") from None
    try:
        root, owner = journal_policy(f)
    except Refusal as error:
        raise Refusal("freshness_unavailable" if str(error) == "journal_unavailable" else "freshness_invalid") from None
    for publication in proof:
        freshness_signature(publication, root, owner)
    checkpoint_signature(cp, root, owner)
    tip = proof[-1]["body"]
    issued = timestamp(tip["issued_at"])
    try:
        snapshot, max_age = snapshot_base(f, root)
    except Refusal as error:
        if str(error) in {"time_unavailable", "watermark_unavailable"}:
            raise
        raise Refusal("freshness_unavailable" if str(error) == "key_binding_unavailable" else "freshness_snapshot_invalid") from None
    low, high = time_values(f)
    require(timestamp(snapshot["issued_at"]) <= timestamp(cp["body"]["at"]) <= low, "freshness_unavailable")
    try:
        witness = journal_witness(f, root, owner)
    except Refusal as error:
        raise Refusal("freshness_unavailable" if str(error) == "journal_unavailable" else "freshness_witness_invalid") from None
    require(f.get("witness_read_at") is not None, "freshness_unavailable")
    try:
        read_at = timestamp(f["witness_read_at"])
    except Refusal:
        raise Refusal("freshness_witness_invalid") from None
    snapshot_id = digest((OWN_TAGS["revocation/1"]+"\n").encode("ascii")+ccj(snapshot))
    require(tip["snapshot"] == snapshot_id == cp["body"]["snapshot"]
            and tip["registry_seq"] == cp["body"]["seq"]
            and tip["checkpoint_id"] == cp["id"], "freshness_binding_mismatch")
    require(tip["registry_seq"] <= witness["registry_seq"], "freshness_unavailable")
    require(tip["registry_seq"] >= witness["registry_seq"], "freshness_rollback")
    require(cp["id"] == witness["checkpoint_id"] and cp["body"]["head"] == witness["registry_head"], "freshness_fork")
    require(issued <= low and high-issued <= max_age and timestamp(cp["body"]["at"]) <= issued
            and issued <= read_at <= low and high-read_at <= max_age, "freshness_unavailable")
    anchor = publication_anchor(f, root, owner)
    seq, previous = anchor["publication_seq"], anchor["freshness_id"]
    at = timestamp(anchor["issued_at"]) if anchor["issued_at"] is not None else None
    registry_seq, checkpoint_id, snapshot_ref = anchor["registry_seq"], anchor["checkpoint_id"], anchor["snapshot"]
    if reanchor:
        require(seq > 0 and at is not None, "freshness_state_invalid")
        require(tip["registry_seq"] >= registry_seq, "freshness_rollback")
        if tip["registry_seq"] == registry_seq:
            require(tip["checkpoint_id"] == checkpoint_id, "freshness_fork")
            require(tip["snapshot"] == snapshot_ref, "freshness_binding_mismatch")
        else:
            require(tip["checkpoint_id"] != checkpoint_id, "freshness_binding_mismatch")
        require(tip["publication_seq"] > seq, "freshness_rollback")
        require(issued > at, "freshness_rollback")
    else:
        for index, publication in enumerate(proof):
            b = publication["body"]
            n, when = b["publication_seq"], timestamp(b["issued_at"])
            require(n >= seq, "freshness_rollback")
            if n == seq:
                require(publication["id"] == previous, "freshness_fork")
                require(index == 0 and at is not None and when == at and b["registry_seq"] == registry_seq
                        and b["checkpoint_id"] == checkpoint_id and b["snapshot"] == snapshot_ref, "freshness_state_invalid")
                continue
            require(n == seq+1, "freshness_gap")
            require(b["registry_seq"] >= registry_seq, "freshness_rollback")
            same_head = b["registry_seq"] == registry_seq
            if same_head:
                require(b["checkpoint_id"] == checkpoint_id, "freshness_fork")
                expected_prev = previous
            else:
                require(b["checkpoint_id"] != checkpoint_id, "freshness_binding_mismatch")
                expected_prev = None
            require(b["prev"] == expected_prev, "freshness_gap")
            require(at is None or when > at, "freshness_time_invalid")
            if same_head:
                require(b["snapshot"] == snapshot_ref, "freshness_binding_mismatch")
            seq, previous, at = n, publication["id"], when
            registry_seq, checkpoint_id, snapshot_ref = b["registry_seq"], b["checkpoint_id"], b["snapshot"]
    try:
        require(type(inp["ids"]) is list and type(inp["keys"]) is list
                and len(inp["ids"]) <= 64 and len(inp["keys"]) <= 64, "freshness_request_invalid")
        for content_id in inp["ids"]:
            hash_id(content_id)
        for key_id in inp["keys"]:
            key_bytes(key_id)
    except Refusal:
        raise Refusal("freshness_request_invalid") from None
    require(not any(timestamp(e["from"]) <= high and e["id"] in inp["keys" if e["kind"] == "key" else "ids"]
                    for e in snapshot["entries"]), "revoked")
    return proof + [cp, {"id": snapshot_id}]



# Version 2 derives latest selection from protected complete-prefix state.
# This implementation does not call Go or trust a registry-signed projection.
def currency_kind(raw):
    # The bounded discriminator is never a schema verdict or an untyped value.
    if len(raw) > 8192:
        return ""
    try:
        e = parse(raw)
        if type(e) is not dict or type(e.get("body")) is not dict:
            return ""
        kind = e["body"].get("type")
        return kind if type(kind) is str else ""
    except Refusal:
        return ""


def currency_list(value, code):
    try:
        require(type(value) is list and 1 <= len(value) <= 3, code)
        roles, keys, previous = set(), set(), ""
        for row in value:
            exact(row, "root_role root_key_id snapshot_id")
            role, key = row["root_role"], row["root_key_id"]
            require(type(role) is str and role in {"grant", "operator", "registry-owner"}, code)
            key_bytes(key); hash_id(row["snapshot_id"])
            order = role+"\0"+key
            require(role not in roles and key not in keys and order > previous, code)
            previous = order; roles.add(role); keys.add(key)
        require("registry-owner" in roles, code)
        return value
    except Refusal:
        raise Refusal(code) from None


def currency_pins(f):
    root_role_separation(f)
    p = evidence_exact(f.get("agent_revocation_root"), "key purpose attestation_root")
    key_bytes(p["key"])
    out = {"registry-owner": p["key"]}
    for role, name in (("grant", "root"), ("operator", "operator_root")):
        if name in f:
            key_bytes(f[name]); out[role] = f[name]
    return out


def currency_wire(raw, checkpoint):
    code = "journal_malformed" if checkpoint else "freshness_malformed"
    try:
        require(len(raw) <= 8192, code)
        e = parse(raw); exact(e, "version body id signatures")
        require(type(e["version"]) is str, code); hash_id(e["id"])
        b = e["body"]
        exact(b, "type registry owner seq head at snapshots" if checkpoint else
              "type registry owner publication_seq prev issued_at snapshots registry_seq checkpoint_id")
        require(type(b["type"]) is str, code); key_bytes(b["registry"]); bounded_text(b["owner"])
        currency_list(b["snapshots"], code)
        for name in (("seq",) if checkpoint else ("publication_seq", "registry_seq")):
            require(type(b[name]) is int and 1 <= b[name] <= 9007199254740991, code)
        if checkpoint:
            hash_id(b["head"]); timestamp(b["at"])
        else:
            require(b["publication_seq"] != 1 or b["prev"] is None, code)
            if b["prev"] is not None: hash_id(b["prev"])
            timestamp(b["issued_at"]); hash_id(b["checkpoint_id"])
        require(type(e["signatures"]) is list and 1 <= len(e["signatures"]) <= 8, code)
        for sig in e["signatures"]:
            exact(sig, "role key sig"); key_bytes(sig["key"])
            require(type(sig["role"]) is str, code); unb64(sig["sig"], 64)
        return e
    except Refusal:
        raise Refusal(code) from None


def currency_signature(e, kind, root, owner, code):
    try:
        b, signatures = e["body"], e["signatures"]
        require(len(signatures) == 1, code); sig = signatures[0]
        require(e["version"] == "swarm-envelope/2" and b["type"] == kind and b["registry"] == root
                and b["owner"] == owner and sig["key"] == root and sig["role"] == "author", code)
        require(e["id"] == digest((OWN_TAGS[kind]+"\n").encode("ascii")+ccj(b)), code)
        verify_signature(root, unb64(sig["sig"], 64), signing_preimage(b, root, "author", kind))
    except Refusal:
        raise Refusal(code) from None


def currency_version(raw, kind):
    k = currency_kind(raw)
    if k in {"checkpoint/1", "checkpoint/2", "freshness/1", "freshness/2"}:
        require(k == kind, "registry_currency_version_mismatch")


def currency_cost(value):
    cost = 16
    if type(value) is str: return cost+len(value.encode("utf-8"))
    if type(value) is bytes: return cost+len(value)
    if type(value) is list: return cost+sum(currency_cost(x) for x in value)
    if type(value) is dict: return cost+sum(len(k.encode("utf-8"))+currency_cost(v) for k, v in value.items())
    return cost


def currency_capacity(f, raws, code):
    def raw_value(v):
        if v is None: return None
        try: return unb64(v)
        except Refusal: return v
    def converted(name, value):
        if type(value) is not dict: return value
        if name == "seen": return {k: raw_value(v) for k, v in value.items()}
        if name == "revocations": return {k: ({n: raw_value(x) if n == "snapshot" else x for n, x in row.items()}
                                               if type(row) is dict else row) for k, row in value.items()}
        if name == "snapshot_journal": return {k: [raw_value(x) for x in v] if k == "entries" and type(v) is list else v for k, v in value.items()}
        return value
    names = ("snapshot_journal", "revocations", "seen", "freshness_anchor", "journal_witness",
             "agent_revocation_root", "registry_owner", "root", "operator_root", "service_root", "witness_read_at")
    values = {name: converted(name, f[name]) for name in names if name in f}
    require(65536+sum(map(len, raws))+sum(currency_cost(v) for v in values.values()) <= 2*1024*1024, code)
    def visit(value):
        if type(value) is bytes: require(len(value) <= 8192, code)
        elif type(value) is list:
            for x in value: visit(x)
        elif type(value) is dict:
            for x in value.values(): visit(x)
    for name in ("snapshot_journal", "revocations", "seen"): visit(values.get(name))


def currency_original(f, id, root):
    require(f.get("id_journal_available") is True and f.get("seen") is not None, "journal_unavailable")
    require(type(f["seen"]) is dict, "journal_invalid")
    require(f["seen"].get(id) is not None, "journal_unavailable")
    try:
        e = signed_evidence(f["seen"][id], "revocation/1", root); b = e["body"]
        require(e["id"] == id, "journal_invalid"); exact(b, "type issuer issued_at complete entries")
        require(b["complete"] is True and type(b["entries"]) is list and len(b["entries"]) <= 64, "journal_invalid")
        timestamp(b["issued_at"]); snapshot_entries(b, 0, [], [])
        return e
    except Refusal:
        raise Refusal("journal_invalid") from None


def currency_anchor(f, root, owner, pins):
    require(f.get("snapshot_journal") is not None, "journal_unavailable")
    try:
        proof = f["snapshot_journal"]; exact(proof, "anchor entries"); a = proof["anchor"]
        exact(a, "version registry_id owner registry_seq registry_head checkpoint_id latest")
        require(type(a["version"]) is int and a["version"] == 2 and a["registry_id"] == root and a["owner"] == owner
                and type(a["registry_seq"]) is int and 0 <= a["registry_seq"] <= 9007199254740991, "journal_invalid")
        if a["registry_seq"] == 0:
            require(a["registry_head"] is None and a["checkpoint_id"] is None, "journal_invalid")
        else:
            hash_id(a["registry_head"]); hash_id(a["checkpoint_id"])
        require(type(a["latest"]) is list and len(a["latest"]) == len(pins), "journal_invalid")
        previous = ""; seen = set()
        for row in a["latest"]:
            exact(row, "root_role root_key_id snapshot_id record_seq")
            role = row["root_role"]
            require(type(role) is str and pins.get(role) == row["root_key_id"] and bool(row["root_key_id"])
                    and role > previous and role not in seen and type(row["record_seq"]) is int, "journal_invalid")
            previous = role; seen.add(role)
            if row["snapshot_id"] is None:
                require(row["record_seq"] == 0, "journal_invalid")
            else:
                hash_id(row["snapshot_id"])
                require(1 <= row["record_seq"] <= a["registry_seq"], "journal_invalid")
        # Return fresh mutable projection, not aliases into the protected premise.
        state = dict(a); state["latest"] = [dict(row) for row in a["latest"]]
    except Refusal:
        raise Refusal("journal_invalid") from None
    for row in state["latest"]:
        if row["snapshot_id"] is not None: currency_original(f, row["snapshot_id"], row["root_key_id"])
    return state


def currency_entries(f):
    require(f.get("snapshot_journal") is not None, "journal_unavailable")
    proof = f["snapshot_journal"]
    require(type(proof) is dict and set(proof) == {"anchor", "entries"} and type(proof["entries"]) is list, "journal_invalid")
    require(len(proof["entries"]) <= 64, "journal_malformed")
    try:
        raws = [unb64(x) for x in proof["entries"]]
        require(all(len(x) <= 8192 for x in raws), "journal_malformed")
        return raws
    except Refusal:
        raise Refusal("journal_malformed") from None


def currency_derive(f, root, owner, pins, raws, cp):
    try: return currency_derive_inner(f, root, owner, pins, raws, cp)
    except Refusal as e:
        if str(e).startswith(("journal_", "checkpoint_")): raise
        raise Refusal("journal_invalid") from None


def currency_derive_inner(f, root, owner, pins, raws, cp):
    state = currency_anchor(f, root, owner, pins); b = cp["body"]
    seq, head, at = state["registry_seq"], state["registry_head"], 0
    require(len(raws) <= 64, "journal_malformed")
    require(b["seq"] >= seq, "journal_rollback")
    if b["seq"] == seq:
        require(cp["id"] == state["checkpoint_id"] and b["head"] == head, "journal_fork")
    elif seq > 0:
        require(f.get("id_journal_available") is True and type(f.get("seen")) is dict, "journal_unavailable")
        original = f["seen"].get(state["checkpoint_id"]); require(original is not None, "journal_unavailable")
        raw = unb64(original)
        if currency_kind(raw) == "checkpoint/1":
            prior = journal_wire(raw, True); checkpoint_signature(prior, root, owner)
        else:
            prior = currency_wire(raw, True); currency_signature(prior, "checkpoint/2", root, owner, "checkpoint_invalid")
        require(prior["id"] == state["checkpoint_id"] and prior["body"]["seq"] == seq and prior["body"]["head"] == head, "checkpoint_invalid")
        require(timestamp(b["at"]) >= timestamp(prior["body"]["at"]), "journal_rollback")
        require(bool(raws), "journal_anchor_required")
        first = journal_wire(raws[0], False)
        require(first["body"]["seq"] == seq and first["id"] == head, "journal_anchor_required")
    for index, raw in enumerate(raws):
        e = journal_wire(raw, False); x = e["body"]; when = timestamp(x["at"])
        require(e["version"] == "swarm-envelope/2" and x["type"] == "journal-entry/1" and x["registry"] == root and x["owner"] == owner
                and e["id"] == digest((OWN_TAGS["journal-entry/1"]+"\n").encode("ascii")+ccj(x)), "journal_entry_invalid")
        if index == 0 and x["seq"] == seq:
            require(e["id"] == head and when <= timestamp(b["at"]), "journal_chain_broken"); at = when; continue
        require(x["seq"] == seq+1 and x["prev"] == head and at <= when <= timestamp(b["at"]), "journal_chain_broken")
        seq, head, at = x["seq"], e["id"], when
        if x["op"] != "add" or x["record_type"] != "revocation/1": continue
        require(f.get("id_journal_available") is True and type(f.get("seen")) is dict, "journal_unavailable")
        original = f["seen"].get(x["record"]); require(original is not None, "journal_unavailable")
        raw = unb64(original); e = parse(raw); exact(e, "version body id signatures")
        body = e["body"]; require(type(body) is dict, "journal_invalid")
        issuer = body.get("issuer"); key_bytes(issuer)
        next_record = currency_original(f, x["record"], issuer); new = next_record["body"]
        require(timestamp(new["issued_at"]) <= when, "journal_invalid")
        for row in state["latest"]:
            if row["root_key_id"] != issuer: continue
            if row["snapshot_id"] is not None:
                if row["snapshot_id"] == x["record"]: break
                old = currency_original(f, row["snapshot_id"], issuer)["body"]
                extends = timestamp(new["issued_at"]) > timestamp(old["issued_at"]) and all(
                    any(n["kind"] == p["kind"] and n["id"] == p["id"] and timestamp(n["from"]) <= timestamp(p["from"])
                        for n in new["entries"]) for p in old["entries"])
                require(extends, "journal_invalid")
            row["snapshot_id"], row["record_seq"] = x["record"], seq
            break
    require(seq == b["seq"] and head == b["head"], "journal_chain_broken")
    for selected in currency_list(b["snapshots"], "journal_malformed"):
        require(any(row["root_role"] == selected["root_role"] and row["root_key_id"] == selected["root_key_id"]
                    and row["snapshot_id"] == selected["snapshot_id"] for row in state["latest"]), "checkpoint_snapshot_invalid")
    state.update(registry_seq=seq, registry_head=head, checkpoint_id=cp["id"])
    return state


def currency_fresh_anchor(f, root, owner):
    require(f.get("freshness_anchor") is not None, "freshness_unavailable")
    a = f["freshness_anchor"]
    if type(a) is dict and "snapshot" in a:
        a = publication_anchor(f, root, owner)
        return a, [{"root_role": "registry-owner", "root_key_id": root, "snapshot_id": a["snapshot"]}], 1
    try:
        exact(a, "registry_id owner publication_seq freshness_id issued_at snapshots registry_seq checkpoint_id")
        require(a["registry_id"] == root and a["owner"] == owner and type(a["publication_seq"]) is int
                and 0 <= a["publication_seq"] <= 9007199254740991 and type(a["registry_seq"]) is int
                and 1 <= a["registry_seq"] <= 9007199254740991, "freshness_state_invalid")
        hash_id(a["checkpoint_id"])
        if a["publication_seq"] == 0: require(a["freshness_id"] is None and a["issued_at"] is None, "freshness_state_invalid")
        else: hash_id(a["freshness_id"]); timestamp(a["issued_at"])
        return a, currency_list(a["snapshots"], "freshness_state_invalid"), 2
    except Refusal:
        raise Refusal("freshness_state_invalid") from None


def currency_bases(f, selections, cp, unavailable, invalid):
    out, age = [], 60
    for row in selections:
        try: body, limit = snapshot_base(f, row["root_key_id"])
        except Refusal as e:
            if str(e) in {"time_unavailable", "watermark_unavailable"}: raise
            raise Refusal(unavailable if str(e) == "key_binding_unavailable" else invalid) from None
        id = digest((OWN_TAGS["revocation/1"]+"\n").encode("ascii")+ccj(body))
        require(id == row["snapshot_id"], invalid)
        require(timestamp(body["issued_at"]) <= timestamp(cp["body"]["at"]), unavailable)
        out.append({"id": id, "body": body}); age = min(age, limit)
    return out, age


def currency_plan(records, state, f, raws=None):
    ids = []
    def add(id):
        if id is not None and id not in ids: ids.append(id)
    for record in records: add(record["id"])
    anchor = f["snapshot_journal"]["anchor"]; add(anchor["checkpoint_id"])
    for row in anchor["latest"]: add(row["snapshot_id"])
    for raw in (currency_entries(f) if raws is None else raws):
        e = journal_wire(raw, False); add(e["id"]); b = e["body"]
        if b["op"] == "add" and b["record_type"] == "revocation/1": add(b["record"])
    return {"ids": ids, "watermark": max(f["now"], f["watermark"]), "snapshot_journal": state}


def currency_fresh(inp, f, reanchor=False):
    require(type(inp["chain"]) is list and bool(inp["chain"]), "freshness_unavailable")
    require(len(inp["chain"]) <= 64 and (not reanchor or len(inp["chain"]) == 1), "freshness_malformed")
    raws = [unb64(x) for x in inp["chain"]]; raw_cp = unb64(inp["checkpoint"])
    require(all(len(x) <= 8192 for x in raws) and sum(map(len, raws))+len(raw_cp) <= 532480, "freshness_malformed")
    for raw in raws: currency_version(raw, "freshness/2")
    currency_version(raw_cp, "checkpoint/2")
    proof = [currency_wire(raw, False) for raw in raws]
    try: cp = currency_wire(raw_cp, True)
    except Refusal: raise Refusal("freshness_malformed") from None
    currency_capacity(f, raws+[raw_cp], "freshness_malformed")
    require(type(f.get("registry_currency_version", 0)) is int and f.get("registry_currency_version", 0) in {0, 1, 2}, "freshness_invalid")
    require(f.get("registry_currency_version", 0) == 2, "registry_currency_version_mismatch")
    try: root, owner = journal_policy(f)
    except Refusal as e: raise Refusal("freshness_unavailable" if str(e) == "journal_unavailable" else "freshness_invalid") from None
    try: pins = currency_pins(f)
    except Refusal: raise Refusal("freshness_invalid") from None
    for e in proof+[cp]:
        require(all(pins.get(x["root_role"]) == x["root_key_id"] for x in e["body"]["snapshots"]), "freshness_invalid")
    for e in proof: currency_signature(e, "freshness/2", root, owner, "freshness_signature_invalid")
    currency_signature(cp, "checkpoint/2", root, owner, "checkpoint_invalid")
    tip = proof[-1]; b, cb = tip["body"], cp["body"]; issued = timestamp(b["issued_at"])
    snaps, age = currency_bases(f, cb["snapshots"], cp, "freshness_unavailable", "freshness_snapshot_invalid")
    low, high = time_values(f); require(timestamp(cb["at"]) <= low, "freshness_unavailable")
    try: w = journal_witness(f, root, owner)
    except Refusal as e: raise Refusal("freshness_unavailable" if str(e) == "journal_unavailable" else "freshness_witness_invalid") from None
    require(f.get("witness_read_at") is not None, "freshness_unavailable")
    try: read = timestamp(f["witness_read_at"])
    except Refusal: raise Refusal("freshness_witness_invalid") from None
    require(b["snapshots"] == cb["snapshots"] and b["registry_seq"] == cb["seq"] and b["checkpoint_id"] == cp["id"], "freshness_binding_mismatch")
    try: state = currency_derive(f, root, owner, pins, currency_entries(f), cp)
    except Refusal as e:
        raise Refusal({"journal_unavailable": "freshness_unavailable", "checkpoint_snapshot_invalid": "freshness_binding_mismatch"}.get(str(e), "freshness_state_invalid")) from None
    require(b["registry_seq"] <= w["registry_seq"], "freshness_unavailable")
    require(b["registry_seq"] >= w["registry_seq"], "freshness_rollback")
    require(cp["id"] == w["checkpoint_id"] and cb["head"] == w["registry_head"], "freshness_fork")
    require(issued <= low and high-issued <= age and timestamp(cb["at"]) <= issued and issued <= read <= low and high-read <= age, "freshness_unavailable")
    a, oldset, oldversion = currency_fresh_anchor(f, root, owner)
    seq, previous = a["publication_seq"], a["freshness_id"]
    at = timestamp(a["issued_at"]) if a["issued_at"] is not None else None
    regseq, cpid = a["registry_seq"], a["checkpoint_id"]
    if oldversion == 1: require(cb["seq"] > regseq, "freshness_binding_mismatch")
    plan = currency_plan(proof+[cp]+snaps, state, f)
    if reanchor:
        require(seq > 0 and at is not None, "freshness_state_invalid")
        require(b["registry_seq"] >= regseq, "freshness_rollback")
        if b["registry_seq"] == regseq:
            require(b["checkpoint_id"] == cpid, "freshness_fork"); require(b["snapshots"] == oldset, "freshness_binding_mismatch")
        else: require(b["checkpoint_id"] != cpid, "freshness_binding_mismatch")
        require(b["publication_seq"] > seq and issued > at, "freshness_rollback")
        plan["reanchor"] = {"reanchored": True, "skipped_publications": b["publication_seq"]-seq-1,
                            "old_freshness_id": previous, "new_freshness_id": tip["id"],
                            "old_checkpoint_id": cpid, "new_checkpoint_id": cp["id"],
                            "old_snapshots": oldset, "new_snapshots": b["snapshots"],
                            "old_registry_currency_version": oldversion, "new_registry_currency_version": 2}
    else:
        for i, publication in enumerate(proof):
            p = publication["body"]; n, when = p["publication_seq"], timestamp(p["issued_at"])
            require(n >= seq, "freshness_rollback")
            if n == seq:
                require(publication["id"] == previous, "freshness_fork")
                require(i == 0 and at is not None and when == at and p["registry_seq"] == regseq and p["checkpoint_id"] == cpid and p["snapshots"] == oldset, "freshness_state_invalid")
                continue
            require(n == seq+1, "freshness_gap"); require(p["registry_seq"] >= regseq, "freshness_rollback")
            same = p["registry_seq"] == regseq
            if same: require(p["checkpoint_id"] == cpid, "freshness_fork")
            else: require(p["checkpoint_id"] != cpid, "freshness_binding_mismatch")
            require(p["prev"] == (previous if same else None), "freshness_gap")
            require(at is None or when > at, "freshness_time_invalid")
            if same: require(p["snapshots"] == oldset, "freshness_binding_mismatch")
            seq, previous, at = n, publication["id"], when
            regseq, cpid, oldset = p["registry_seq"], p["checkpoint_id"], p["snapshots"]
    try:
        require(type(inp["ids"]) is list and type(inp["keys"]) is list and len(inp["ids"]) <= 64 and len(inp["keys"]) <= 64, "freshness_request_invalid")
        for id in inp["ids"]: hash_id(id)
        for id in inp["keys"]: key_bytes(id)
    except Refusal: raise Refusal("freshness_request_invalid") from None
    for row, snap in zip(cb["snapshots"], snaps):
        if row["root_role"] == "registry-owner": snapshot_entries(snap["body"], high, inp["ids"], inp["keys"])
    return plan, tip, cp, age


def currency_journal(inp, f):
    require(type(inp["entries"]) is list and len(inp["entries"]) <= 64, "journal_malformed")
    raws = [unb64(x) for x in inp["entries"]]; raw_cp = unb64(inp["checkpoint"]); conflict = unb64(inp["conflict"]) if "conflict" in inp else b""
    require(all(len(x) <= 8192 for x in raws+[raw_cp, conflict]) and sum(map(len, raws+[raw_cp, conflict])) <= 540672, "journal_malformed")
    currency_version(raw_cp, "checkpoint/2")
    if conflict: currency_version(conflict, "checkpoint/2")
    for raw in raws: journal_wire(raw, False)
    cp = currency_wire(raw_cp, True); other = None
    if conflict: other = currency_wire(conflict, True)
    currency_capacity(f, raws+[raw_cp, conflict], "journal_malformed")
    require(type(f.get("registry_currency_version", 0)) is int and f.get("registry_currency_version", 0) in {0, 1, 2}, "journal_invalid")
    require(f.get("registry_currency_version", 0) == 2, "registry_currency_version_mismatch")
    root, owner = journal_policy(f)
    try: pins = currency_pins(f)
    except Refusal: raise Refusal("journal_invalid") from None
    for e in [cp]+([other] if other else []):
        require(all(pins.get(x["root_role"]) == x["root_key_id"] for x in e["body"]["snapshots"]), "journal_invalid")
        currency_signature(e, "checkpoint/2", root, owner, "checkpoint_invalid")
        low, high = time_values(f); at = timestamp(e["body"]["at"])
        require(at <= low and high-at <= 60, "journal_unavailable")
        _, age = currency_bases(f, e["body"]["snapshots"], e, "journal_unavailable", "checkpoint_snapshot_invalid")
        require(high-at <= age, "journal_unavailable")
    w = journal_witness(f, root, owner); b = cp["body"]
    if other: require(b["seq"] != other["body"]["seq"] or (b["head"] == other["body"]["head"] and cp["id"] == other["id"]), "journal_fork")
    require(b["seq"] >= w["registry_seq"], "journal_rollback")
    if b["seq"] == w["registry_seq"]: require(b["head"] == w["registry_head"] and cp["id"] == w["checkpoint_id"], "journal_fork")
    a = currency_anchor(f, root, owner, pins)
    require(a["registry_seq"] == w["registry_seq"] and a["registry_head"] == w["registry_head"] and a["checkpoint_id"] == w["checkpoint_id"], "journal_invalid")
    currency_entries(f)
    state = currency_derive(f, root, owner, pins, raws, cp)
    return currency_plan([cp], state, f, raws)


def currency_pin_facts(f):
    return {name: f[name] for name in ("root", "operator_root", "agent_revocation_root", "service_root", "commit_signing_key", "enrollment_publisher", "operator_owner", "service_authority") if name in f}


_JOURNAL_IDENTITY = object()


def currency_proof_shape(value):
    exact(value, "anchor entries")
    a = value["anchor"]
    exact(a, "version registry_id owner registry_seq registry_head checkpoint_id latest")
    require(type(a["version"]) is int and a["version"] == 2 and type(a["registry_seq"]) is int and 0 <= a["registry_seq"] <= 9007199254740991, "freshness_receipt_invalid")
    key_bytes(a["registry_id"]); bounded_text(a["owner"])
    if a["registry_seq"] == 0:
        require(a["registry_head"] is None and a["checkpoint_id"] is None, "freshness_receipt_invalid")
    else:
        hash_id(a["registry_head"]); hash_id(a["checkpoint_id"])
    require(type(a["latest"]) is list and 1 <= len(a["latest"]) <= 3, "freshness_receipt_invalid")
    previous, seen = "", set()
    for row in a["latest"]:
        exact(row, "root_role root_key_id snapshot_id record_seq")
        role = row["root_role"]
        key_bytes(row["root_key_id"])
        require(role in ("grant", "operator", "registry-owner") and role > previous and row["root_key_id"] not in seen and type(row["record_seq"]) is int, "freshness_receipt_invalid")
        previous = role; seen.add(row["root_key_id"])
        if row["snapshot_id"] is None:
            require(row["record_seq"] == 0, "freshness_receipt_invalid")
        else:
            hash_id(row["snapshot_id"])
            require(1 <= row["record_seq"] <= a["registry_seq"], "freshness_receipt_invalid")
    require(type(value["entries"]) is list and len(value["entries"]) <= 64, "freshness_receipt_invalid")
    for raw in value["entries"]:
        require(type(raw) is str and len(unb64(raw)) <= 8192, "freshness_receipt_invalid")


def currency_receipt_gate(f, low, high, ctx):
    r, margin, identity, _ = ctx
    require(r is not None, "freshness_receipt_unavailable")
    require(type(margin) is int and 0 <= margin <= 60, "freshness_receipt_invalid")
    for name in ("agent_revocation_root", "registry_owner", "journal_witness", "freshness_anchor", "witness_read_at", "revocations", "snapshot_journal"):
        require(f.get(name) is not None, "freshness_receipt_unavailable")
    for name in r["pin_facts"]: require(f.get(name) is not None, "freshness_receipt_unavailable")
    receipt_presence(f["agent_revocation_root"], "key purpose attestation_root")
    receipt_presence(f["journal_witness"], "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id", ("previous_checkpoint_id",))
    receipt_presence(f["freshness_anchor"], "registry_id owner publication_seq freshness_id issued_at snapshots registry_seq checkpoint_id", ("freshness_id", "issued_at"))
    receipt_presence(f["snapshot_journal"], "anchor entries")
    proof = f["snapshot_journal"]
    if type(proof) is dict:
        receipt_presence(proof.get("anchor"), "version registry_id owner registry_seq registry_head checkpoint_id latest", ("registry_head", "checkpoint_id"))
        a = proof.get("anchor")
        if type(a) is dict and type(a.get("latest")) is list:
            for row in a["latest"]:
                receipt_presence(row, "root_role root_key_id snapshot_id record_seq", ("snapshot_id",))
    records = f["revocations"]
    if type(records) is dict:
        for key in r["snapshots"]:
            require(records.get(key) is not None, "freshness_receipt_unavailable"); receipt_presence(records[key], "snapshot")
    try:
        pins = currency_pins(f); policy = evidence_exact(f["agent_revocation_root"], "key purpose attestation_root")
        key_bytes(policy["attestation_root"]); require(policy["purpose"] == "registry-revocation", "freshness_receipt_invalid"); bounded_text(f["registry_owner"])
        w = f["journal_witness"]; exact(w, "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id")
        key_bytes(w["registry_id"]); bounded_text(w["owner"]); witness = journal_witness(f, w["registry_id"], w["owner"])
        a = f["freshness_anchor"]; exact(a, "registry_id owner publication_seq freshness_id issued_at snapshots registry_seq checkpoint_id")
        key_bytes(a["registry_id"]); bounded_text(a["owner"]); anchor, _, _ = currency_fresh_anchor(f, a["registry_id"], a["owner"])
        currency_proof_shape(f["snapshot_journal"]); read = timestamp(f["witness_read_at"])
        require(read <= low and type(records) is dict, "freshness_receipt_invalid")
        for key in r["snapshots"]:
            require(type(records[key]) is dict and type(records[key]["snapshot"]) is str, "freshness_receipt_invalid")
    except Refusal: raise Refusal("freshness_receipt_invalid") from None
    require(f.get("registry_currency_version") == 2 and r["version"] == 2, "freshness_receipt_binding_mismatch")
    require(pins == r["pins"] and currency_pin_facts(f) == r["pin_facts"] and f["registry_owner"] == r["owner"], "freshness_receipt_binding_mismatch")
    require(identity is r["identity"] and f.get(_JOURNAL_IDENTITY) is r["journal_identity"], "freshness_receipt_binding_mismatch")
    require(all(witness[k] == value for k, value in r["witness"].items()) and anchor == r["anchor"], "freshness_receipt_binding_mismatch")
    require(all(unb64(records[k]["snapshot"]) == value for k, value in r["snapshots"].items()), "freshness_receipt_binding_mismatch")
    require(read >= r["read"], "freshness_receipt_binding_mismatch")
    require(high < r["expires"]-margin, "freshness_receipt_expired")


def currency_receipt_snapshot(f, root, body, ctx):
    r = ctx[0]
    for row in r["anchor"]["snapshots"]:
        if row["root_key_id"] == root:
            require(row["snapshot_id"] == digest((OWN_TAGS["revocation/1"]+"\n").encode("ascii")+ccj(body)), "freshness_receipt_binding_mismatch")
            return True
    require(not r["required"], "freshness_receipt_unavailable")
    return False


def currency_receipt(inp, facts):
    mint = inp["mint"]; _, tip, cp, age = currency_fresh(mint["input"], facts, mint["mode"] == "freshness-reanchor")
    b = tip["body"]; root = b["registry"]; identity, journal_identity = object(), object()
    anchor = {"registry_id": root, "owner": b["owner"], "publication_seq": b["publication_seq"], "freshness_id": tip["id"], "issued_at": b["issued_at"], "snapshots": b["snapshots"], "registry_seq": b["registry_seq"], "checkpoint_id": b["checkpoint_id"]}
    r = {"version": 2, "root": root, "owner": b["owner"], "identity": identity, "journal_identity": journal_identity,
         "anchor": anchor, "pins": currency_pins(facts), "pin_facts": currency_pin_facts(facts), "required": inp["require"],
         "snapshots": {row["root_key_id"]: unb64(facts["revocations"][row["root_key_id"]]["snapshot"]) for row in b["snapshots"]},
         "witness": {k: facts["journal_witness"][k] for k in ("registry_id", "owner", "registry_seq", "registry_head", "checkpoint_id")},
         "read": timestamp(facts["witness_read_at"]), "expires": min(timestamp(b["issued_at"])+age, timestamp(facts["witness_read_at"])+age)}
    f = dict(facts); f["freshness_anchor"] = anchor; f.update(inp["use"])
    if inp["renew_evidence"] or "revocations" in inp["use"]: identity = object()
    if inp.get("renew_journal_evidence") or "snapshot_journal" in inp["use"]: journal_identity = object()
    f[_JOURNAL_IDENTITY] = journal_identity
    mode, operation = inp["consume"]["mode"], inp["consume"]["input"]
    if inp["attach"] or inp["require"]:
        f[_RECEIPT_CONTEXT] = (r if inp["attach"] else None, inp["margin"], identity, operation["root"] if mode == "revocation" else None)
    return receipt_consume(inp, f, mode, operation)


_RECEIPT_CONTEXT = object()


def receipt_presence(value, names, nullable=()):
    # Inspect available members without classifying malformed containers yet.
    if type(value) is dict:
        for name in names.split():
            require(name in value and (value[name] is not None or name in nullable), "freshness_receipt_unavailable")


def receipt_gate(f, low, high):
    ctx = f.get(_RECEIPT_CONTEXT)
    if ctx is None:
        return
    r, margin, identity, explicit_root = ctx
    if r is not None and r.get("version") == 2:
        return currency_receipt_gate(f, low, high, ctx)
    require(r is not None, "freshness_receipt_unavailable")
    require(type(margin) is int and 0 <= margin <= 60, "freshness_receipt_invalid")
    for name in ("agent_revocation_root", "registry_owner", "journal_witness", "freshness_anchor", "witness_read_at", "revocations"):
        require(f.get(name) is not None, "freshness_receipt_unavailable")
    # R2 presence is complete before any key, schema or timestamp parser runs.
    receipt_presence(f["agent_revocation_root"], "key purpose attestation_root")
    receipt_presence(f["journal_witness"], "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id", ("previous_checkpoint_id",))
    receipt_presence(f["freshness_anchor"], "registry_id owner publication_seq freshness_id issued_at snapshot registry_seq checkpoint_id", ("freshness_id", "issued_at"))
    records = f["revocations"]
    if type(records) is dict:
        row = records.get(r["root"])
        require(row is not None, "freshness_receipt_unavailable")
        receipt_presence(row, "snapshot")
    # R2 syntax follows the complete presence stage.
    try:
        policy = evidence_exact(f["agent_revocation_root"], "key purpose attestation_root")
        key_bytes(policy["key"]); key_bytes(policy["attestation_root"])
        require(policy["purpose"] == "registry-revocation", "freshness_receipt_invalid")
        bounded_text(f["registry_owner"])
        # Shape alone preserves permitted nulls for the projection validators.
        w = f["journal_witness"]
        exact(w, "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id")
        key_bytes(w["registry_id"]); bounded_text(w["owner"])
        witness = journal_witness(f, w["registry_id"], w["owner"])
        a = f["freshness_anchor"]
        exact(a, "registry_id owner publication_seq freshness_id issued_at snapshot registry_seq checkpoint_id")
        key_bytes(a["registry_id"]); bounded_text(a["owner"])
        anchor = publication_anchor(f, a["registry_id"], a["owner"])
        read = timestamp(f["witness_read_at"])
        require(read <= low, "freshness_receipt_invalid")
    except Refusal:
        raise Refusal("freshness_receipt_invalid") from None
    require(type(records) is dict, "freshness_receipt_invalid")
    row = records.get(r["root"])
    require(type(row) is dict, "freshness_receipt_invalid")
    require(type(row["snapshot"]) is str, "freshness_receipt_invalid")
    require(policy["key"] == r["root"] and f["registry_owner"] == r["owner"], "freshness_receipt_binding_mismatch")
    require(identity is r["identity"], "freshness_receipt_binding_mismatch")
    require(explicit_root is None or explicit_root == r["root"], "freshness_receipt_binding_mismatch")
    require(all(witness[k] == value for k, value in r["witness"].items()), "freshness_receipt_binding_mismatch")
    require(anchor == r["anchor"], "freshness_receipt_binding_mismatch")
    require(unb64(row["snapshot"]) == r["snapshot"], "freshness_receipt_binding_mismatch")
    require(read >= r["read"], "freshness_receipt_binding_mismatch")
    require(high < r["expires"] - margin, "freshness_receipt_expired")


def receipt_snapshot(f, root, body):
    ctx = f.get(_RECEIPT_CONTEXT)
    if ctx is not None and ctx[0] is not None and ctx[0].get("version") == 2:
        return currency_receipt_snapshot(f, root, body, ctx)
    if ctx is None or ctx[0] is None or root != ctx[0]["root"]:
        return False
    require(digest((OWN_TAGS["revocation/1"]+"\n").encode("ascii")+ccj(body)) == ctx[0]["anchor"]["snapshot"], "freshness_receipt_binding_mismatch")
    return True


def receipt_revocation_policy(f, root):
    # Direct CheckRevocation retains the existing pinned-domain header gate.
    root_role_separation(f)
    require(type(root) is str and bool(root), "key_binding_invalid")
    service, registry = f.get("service_root"), f.get("agent_revocation_root")
    require(type(service) is not dict or root != service.get("key"), "key_binding_invalid")
    if type(registry) is dict and root == registry.get("key"):
        policy = evidence_exact(registry, "key purpose attestation_root")
        issuer = evidence_exact(service, "key purpose")
        require(type(issuer["purpose"]) is int and issuer["purpose"] == 5
                and policy["purpose"] == "registry-revocation" and policy["attestation_root"] == issuer["key"], "key_binding_invalid")
        try:
            key_bytes(issuer["key"]); key_bytes(policy["key"])
        except Refusal:
            raise Refusal("key_binding_invalid") from None
    elif root not in (f.get("operator_root"), f.get("root")):
        evidence_exact(registry, "key purpose attestation_root")
        require(f.get("operator_root") is not None and f.get("root") is not None, "key_binding_unavailable")
        raise Refusal("key_binding_invalid")


def receipt_verdict(inp, facts):
    if facts.get("registry_currency_version") == 2:
        return currency_receipt(inp, facts)
    # The complete real F pipeline, including signatures and revocation, runs
    # before this private object exists. No decoded receipt assertion is trusted.
    mint = inp["mint"]
    es = fresh_revocation(mint["input"], facts, mint["mode"] == "freshness-reanchor")
    tip, cp = es[-3], es[-2]
    b, cb = tip["body"], cp["body"]
    root = b["registry"]
    row = facts["revocations"][root]
    identity = object()
    anchor = {"registry_id": root, "owner": b["owner"], "publication_seq": b["publication_seq"], "freshness_id": tip["id"], "issued_at": b["issued_at"], "snapshot": b["snapshot"], "registry_seq": b["registry_seq"], "checkpoint_id": b["checkpoint_id"]}
    r = {"identity": identity, "root": root, "owner": b["owner"], "snapshot": unb64(row["snapshot"]),
         "anchor": anchor, "witness": {k: facts["journal_witness"][k] for k in ("registry_id", "owner", "registry_seq", "registry_head", "checkpoint_id")},
         "read": timestamp(facts["witness_read_at"]),
         "expires": min(timestamp(b["issued_at"])+row["max_age"], timestamp(facts["witness_read_at"])+row["max_age"])}
    f = dict(facts)
    f["freshness_anchor"] = anchor
    f.update(inp["use"])
    if inp["renew_evidence"] or "revocations" in inp["use"]:
        identity = object()
    mode, operation = inp["consume"]["mode"], inp["consume"]["input"]
    if inp["attach"] or inp["require"]:
        f[_RECEIPT_CONTEXT] = (r if inp["attach"] else None, inp["margin"], identity, operation["root"] if mode == "revocation" else None)
    return receipt_consume(inp, f, mode, operation)


def receipt_consume(inp, f, mode, operation):
    if mode in ("attestation", "device"):
        # This direct API uses an exact reference; device lookup remains by key.
        require(mode == "device" or operation["reference"] != "", "key_binding_unavailable")
        e = verify_attestation(operation["key"], f, mode == "device", True, operation["reference"] if mode == "attestation" else None, direct=True)
        require(mode != "device" or operation["reference"] == "" or e["id"] == operation["reference"], "key_binding_invalid")
        return {"code": "accept", "plan": {}}
    if mode == "revocation":
        receipt_revocation_policy(f, operation["root"])
        signed_snapshot(f, operation["root"], operation["ids"], operation["keys"])
        return {"code": "accept", "plan": {}}
    if mode == "service":
        service_identity(operation["key"], f)
        return {"code": "accept", "plan": {}}
    if mode == "grant":
        es = grants(operation["chain"], f)
    else:
        es = [envelope(unb64(operation["envelope"]), "operator-act/1" if mode == "operator" else "message/1", f)]
        if mode == "operator":
            operator(es[0], f)
    plan = {"ids": [e["id"] for e in es], "watermark": max(f["now"], f["watermark"])}
    if mode == "operator":
        plan["action_id"] = es[0]["body"]["action_id"]
    return {"code": "accept", "plan": plan}


def verdict(vector):
    f, inp, mode = vector["fixture"], vector["input"], vector["mode"]
    try:
        if mode == "receipt":
            return receipt_verdict(inp, f)
        if mode == "signer":
            return {"code": "accept", "plan": signer_admission(unb64(inp["preimage"]), f)}
        if mode == "domain":
            return {"code": "accept", "plan": check_domain(inp, f)}
        if mode in ("freshness", "freshness-reanchor", "journal") and f.get("registry_currency_version", 0) not in (0, 1):
            plan = currency_journal(inp, f) if mode == "journal" else currency_fresh(inp, f, mode == "freshness-reanchor")[0]
            return {"code": "accept", "plan": plan}
        if mode in ("freshness", "freshness-reanchor"):
            es = fresh_revocation(inp, f, mode == "freshness-reanchor")
        elif mode == "journal":
            es = identity_journal(inp, f)
        elif mode == "grant":
            es = grants(inp["chain"], f)
        else:
            es = [envelope(unb64(inp["envelope"]), "operator-act/1" if mode == "operator" else "message/1", f)]
            if mode == "operator":
                operator(es[0], f)
        plan = {"ids": [e["id"] for e in es], "watermark": max(f["now"], f["watermark"])}
        if mode == "freshness-reanchor":
            anchor, tip = f["freshness_anchor"], es[0]
            plan["reanchor"] = {
                "reanchored": True,
                "skipped_publications": tip["body"]["publication_seq"] - anchor["publication_seq"] - 1,
                "old_freshness_id": anchor["freshness_id"], "new_freshness_id": tip["id"],
                "old_checkpoint_id": anchor["checkpoint_id"], "new_checkpoint_id": tip["body"]["checkpoint_id"],
            }
        if mode == "operator":
            plan["action_id"] = es[0]["body"]["action_id"]
        return {"code": "accept", "plan": plan}
    except Refusal as error:
        return {"code": str(error), "plan": {}}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vectors", default="vectors", type=Path)
    args = ap.parse_args()
    paths = sorted((args.vectors / "swarm-envelope-2").glob("*/*.json"))
    if not paths:
        print("FAIL: no vectors", file=sys.stderr)
        return 1
    rows = [json.loads(p.read_text()) for p in paths]
    positives = {v["id"] for v in rows if v["expected"]["code"] == "accept"}
    failed = 0
    for path, vector in zip(paths, rows):
        got = verdict(vector)
        paired = vector["positive_control"] in positives if vector["expected"]["code"] != "accept" else vector["positive_control"] == ""
        if got != vector["expected"] or not paired:
            failed += 1
            print(f"FAIL {path.name}: derived={got}, expected={vector['expected']}, paired={paired}", file=sys.stderr)
    print(f"{len(rows)} independently checked: {len(rows)-len(positives)} negative, {len(positives)} positive; failures={failed}")
    if ec is None:
        print("PENDING: P-256 requires cryptography; Ed25519 uses pure Python", file=sys.stderr)
        return 2
    return int(failed != 0)


if __name__ == "__main__":
    sys.exit(main())
