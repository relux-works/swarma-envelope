# Public test keys only

Every seed and derived private scalar in this directory is public test material.
Never enroll these keys, use them for deployment, or replace them with real keys.
No operational key is read by either tool.

Ed25519 test-i, i=0..5, uses SHA-256 of ASCII `waggle public test seed i` as its
32-byte seed. P-256 test-6 uses SHA-256 of ASCII `waggle public test p256 seed`;
the scalar is 1 + seed_integer mod (n-1), big-endian. Public encodings are in
public-keys.json. The Go generator contains a deterministic test-only ECDSA
nonce construction to make fixture bytes stable across runs. It is not a
production signer and MUST NOT be imported as one.

The independent checker derives no verdict from this directory or the Go
implementation. It verifies the key ids and signatures actually in each input.
The Go check also compares seed and public-key files byte for byte.
