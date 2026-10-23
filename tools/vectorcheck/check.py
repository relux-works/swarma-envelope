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


def values(value, depth=0):
    if isinstance(value, (dict, list)):
        depth += 1
        require(depth <= 16, "envelope_malformed")
        if isinstance(value, list):
            require(len(value) <= 64, "envelope_malformed")
            for item in value:
                values(item, depth)
        else:
            for key, item in value.items():
                values(key, depth)
                values(item, depth)
    elif isinstance(value, str):
        require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "envelope_malformed")
        require(len(value.encode("utf-8")) <= 8192, "envelope_malformed")


def parse(raw):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=no_number, parse_constant=no_number)
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("envelope_malformed") from None
    values(value)
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
    if not isinstance(value, str) or len(value.encode("utf-8")) > 255:
        return False
    if pattern and value.endswith("/*"):
        value = value[:-2]
    expr = r"[a-z0-9-]+" if single else r"[a-z0-9-]+(?:/[a-z0-9-]+)*"
    return re.fullmatch(expr, value) is not None


def target(value, pattern=False):
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    names = {"kind", "id", "harness", "profile"} if kind == "credential" else {"kind", "id"}
    return (kind in {"credential", "station", "registration", "account"}
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
    extra = {"message/1": "author action target arguments",
             "grant/1": "issuer subject actions targets not_before expires depth parent caveats",
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
        require(target(b["target"]) and b["target"]["kind"] in {"registration", "account"}, "envelope_malformed")
        require(isinstance(b["owner"], str) and 1 <= len(b["owner"].encode("utf-8")) <= 255
                and isinstance(b["epoch"], str) and re.fullmatch(r"[!-~]{1,255}", b["epoch"]), "envelope_malformed")
        unb64(b["action_id"], 16)
        hash_id(b["arguments_digest"])
        require(type(b["confirmed"]) is bool, "envelope_malformed")
    else:
        key_bytes(b["author"])
        require(isinstance(b["action"], str) and target(b["target"])
                and isinstance(b["arguments"], dict), "envelope_malformed")


def time_values(f):
    t = f["time"]
    require(t["trusted"] is True and t["fresh"] is True
            and timestamp(f["now"]) < timestamp(t["authority_until"]), "time_unavailable")
    require(f["watermark_available"] is True, "watermark_unavailable")
    now, watermark = timestamp(f["now"]), timestamp(f["watermark"])
    return min(now, watermark), max(now, watermark)


def window(start, end, low, high):
    require(high < timestamp(end), "expired")
    require(low >= timestamp(start), "not_yet_valid")


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
    require(e["id"] == digest(("waggle " + expected + "\n").encode("ascii")+ccj(b)), "envelope_id_mismatch")
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
        else:
            require(f["known_keys"] is not None, "signer_unavailable")
            require(s["key"] in f["known_keys"], "signer_unknown")
            if expected == "message/1" and s["role"] == "author":
                require(s["key"] == b["author"], "signer_unknown")
        pre = ("waggle swarm-envelope/2 " + expected + " " + s["role"] + "\n").encode("ascii") + ccj({"body": b, "key": s["key"]})
        verify_signature(s["key"], unb64(s["sig"], 64), pre)
    require(b["aud"] == f["audience"], "audience_mismatch")
    low, high = time_values(f)
    window(b["iat"], b["exp"], low, high)
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


def revocation(f, ids, keys):
    r = f["revocation"]
    low, high = time_values(f)
    require(r["verdict"] in {"not_revoked", "revoked"} and r["complete"] and r["rollback_safe"]
            and 0 < r["max_age"] <= 60 and timestamp(r["issued_at"]) <= low
            and high-timestamp(r["issued_at"]) <= r["max_age"], "revocation_unavailable")
    require(r["verdict"] != "revoked" and not set(ids).intersection(r["revoked_ids"])
            and not set(keys).intersection(r["revoked_keys"]), "revoked")


def grants(raw_chain, f):
    require(type(raw_chain) is list and 1 <= len(raw_chain) <= 4, "grant_chain_malformed")
    raw = [unb64(r) for r in raw_chain]
    require(sum(map(len, raw)) <= 262144, "grant_chain_malformed")
    # G1 duplicate IDs require only bounded lexical parse, before envelope crypto.
    ids = [parse(r).get("id") if isinstance(parse(r), dict) else None for r in raw]
    require(all(isinstance(i, str) for i in ids) and len(set(ids)) == len(ids), "grant_chain_malformed")
    req = f["request"]
    require(isinstance(req, dict) and set(req) == {"key", "action", "target"}, "grant_chain_malformed")
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
                and cs >= ps and ce <= pe and child["aud"] == parent["aud"], "grant_not_narrowing")
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
    return es


def operator(e, f):
    b, binding = e["body"], f["binding"]
    operations = {"revoke": ("registration", False), "grant.issue": ("account", True)}
    require(b["operation"] in operations, "act_operation_unknown")
    kind, widening = operations[b["operation"]]
    require(b["operation"] == binding["operation"] and b["target"] == binding["target"]
            and b["target"]["kind"] == kind and b["owner"] == binding["owner"]
            and b["epoch"] == binding["epoch"]
            and b["arguments_digest"] == digest(ccj(binding["arguments"])), "act_binding_mismatch")
    revocation(f, [e["id"]], [s["key"] for s in e["signatures"]])
    if widening:
        require(b["confirmed"], "act_confirmation_required")
        require(f["signer_facts"]["presence"] and f["signer_facts"]["current"], "act_presence_required")
    require(f["replay_available"], "replay_unavailable")
    require(b["action_id"] not in f["used_actions"], "act_replay")


def verdict(vector):
    f, inp, mode = vector["fixture"], vector["input"], vector["mode"]
    try:
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
