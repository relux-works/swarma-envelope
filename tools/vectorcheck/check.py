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
    extra = {"message/1": "author action target arguments room to body_sha256",
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
            "revocation/1": "swarma-attestation revocation/1"}
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
        # These exact paths are each read once after duplicate-free CCJ admission.
        require(type(decoded) is dict, "signer_identity_malformed")
        key = decoded.get("key")
        body = decoded.get("body")
        require(type(body) is dict, "signer_identity_malformed")
        author = body.get("author")
        require(type(key) is str and type(author) is str, "signer_identity_malformed")
        require(key == caller_key and author == caller_key, "signer_identity_mismatch")
    return {"tag": "swarma-msg/2", "preimage_sha256": digest(raw)}


def check_domain(inp, f):
    expected = f["expected_tag"]
    require(expected in REGISTERED_TAGS, "domain_unknown")
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


def signed_snapshot(f, root, ids, keys):
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
    require(b["complete"] and record["rollback_safe"] and issued <= low
            and high-issued <= record["max_age"], "key_binding_unavailable")
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


def verify_attestation(key, f, device=False, check_revocation=True):
    collection = "operator_attestations" if device else "attestations"
    records = evidence_object(f.get(collection))
    require(key in records, "key_binding_unavailable")
    if device:
        root = f.get("operator_root")
        require(root is not None, "key_binding_unavailable")
    else:
        root_record = evidence_exact(f.get("service_root"), "key purpose")
        require(type(root_record["purpose"]) is int and root_record["purpose"] == 5, "key_binding_invalid")
        root = root_record["key"]
    e = signed_evidence(records[key], "attestation/1", root)
    b = evidence_exact(e["body"], "type issuer subject key_class purpose roles actions iat exp binding")
    subject = evidence_exact(b["subject"], "algorithm key_id public_bytes")
    require(all(type(subject[n]) is str for n in subject)
            and all(type(b[n]) is str for n in ("key_class", "purpose", "iat", "exp"))
            and type(b["roles"]) is list and type(b["actions"]) is list, "key_binding_invalid")
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
    require(start <= low and high < end, "key_binding_invalid")
    if check_revocation:
        signed_snapshot(f, root, [e["id"]], [key])
    return e


def agent_binding(key, f):
    verify_attestation(key, f)


def grant_key_binding(key, f):
    # Protected authority-root provenance is independent of algorithm/position.
    if key == f["root"]:
        return
    devices = evidence_object(f.get("operator_attestations"))
    if key in devices:
        verify_attestation(key, f, device=True)
        operator_key_current(f)
    else:
        agent_binding(key, f)


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
    required = (["author"] + f["required_roles"] if expected == "message/1"
                else ["author"] if expected == "grant/1" else ["approver"] + f["required_roles"])
    require(all(s["role"] in {"author", "approver", "delegate"} for s in sigs)
            and len(set(pairs_seen)) == len(sigs)
            and set(required) <= {s["role"] for s in sigs}, "envelope_role_invalid")
    if expected in {"grant/1", "operator-act/1"}:
        require(len(sigs) == 1 and sigs[0]["role"] == ("author" if expected == "grant/1" else "approver"), "envelope_role_invalid")
    require(e["id"] == digest((OWN_TAGS[expected] + "\n").encode("ascii")+ccj(b)), "envelope_id_mismatch")
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
    for s in sigs:
        if expected == "grant/1":
            require(s["key"] == b["issuer"], "signer_unknown")
        elif expected == "message/1" and s["role"] == "author":
            require(f["known_keys"] is not None, "signer_unavailable")
            require(s["key"] in f["known_keys"] and s["key"] == b["author"], "signer_unknown")
        alg, _ = key_bytes(s["key"])
        allowed = ((expected == "message/1" and (s["role"], alg) in {("author", "ed25519"), ("approver", "p256")})
                   or (expected == "operator-act/1" and (s["role"], alg) == ("approver", "p256"))
                   or (expected == "grant/1" and s["role"] == "author" and alg in {"ed25519", "p256"}))
        require(allowed, "signature_profile_invalid")
        pre = signing_preimage(b, s["key"], s["role"], expected)
        if expected == "message/1":
            require(len(pre) <= 24576, "signature_preimage_too_large")
            try:
                values({"version": "swarm-envelope/2", "role": s["role"], "key": s["key"], "body": b}, max_depth=12)
            except Refusal:
                raise Refusal("signature_preimage_invalid") from None
        verify_signature(s["key"], unb64(s["sig"], 64), pre)
    audience = f.get("audience")
    require(type(audience) is str and re.fullmatch(r"[!-~]{1,255}", audience), "audience_mismatch")
    require(b["aud"] == audience, "audience_mismatch")
    if expected == "message/1":
        delivery_binding(b, f)
    low, high = time_values(f)
    window(b["iat"], b["exp"], low, high)
    if expected == "message/1":
        agent_binding(b["author"], f)
        if any(s["role"] == "approver" for s in sigs):
            operator_key_current(f)
            for sig in sigs:
                if sig["role"] == "approver":
                    verify_attestation(sig["key"], f, device=True)

    elif expected == "grant/1":
        for key in (b["issuer"], b["subject"]):
            grant_key_binding(key, f)
    require(f["id_journal_available"], "id_journal_unavailable")
    require(e["id"] not in f["seen"] or unb64(f["seen"][e["id"]]) == raw, "envelope_conflict")
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
        signed_snapshot(f, f["root"] if root is None else root, ids, keys)
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
    req = f["request"]
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
    require(bs[-1]["parent"] is None and bs[-1]["issuer"] == f["root"], "grant_root_unknown")
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
    current = f.get("signer_facts", {}).get("current")
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
    operator_key_current(f)
    attestation = verify_attestation(e["signatures"][0]["key"], f, device=True, check_revocation=False)
    require(attestation["body"]["binding"]["owner"] == b["owner"], "key_binding_invalid")
    revocation(f, [e["id"], attestation["id"]], [s["key"] for s in e["signatures"]], root=f["operator_root"])
    if widening:
        require(b["confirmed"], "act_confirmation_required")
        require(f["signer_facts"]["presence"] is True and f["signer_facts"].get("presence_current") is True, "act_presence_required")
    require(f["replay_available"], "replay_unavailable")
    require(b["action_id"] not in f["used_actions"], "act_replay")
    if widening:
        raise Refusal("act_a3_inactive")


def verdict(vector):
    f, inp, mode = vector["fixture"], vector["input"], vector["mode"]
    try:
        if mode == "signer":
            return {"code": "accept", "plan": signer_admission(unb64(inp["preimage"]), f)}
        if mode == "domain":
            return {"code": "accept", "plan": check_domain(inp, f)}
        if mode == "grant":
            es = grants(inp["chain"], f)
        else:
            es = [envelope(unb64(inp["envelope"]), "operator-act/1" if mode == "operator" else "message/1", f)]
            if mode == "operator":
                operator(es[0], f)
        plan = {"ids": [e["id"] for e in es], "watermark": max(f["now"], f["watermark"])}
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
