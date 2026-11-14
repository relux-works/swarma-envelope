# Official BIP-340 vectors

Unmodified `test-vectors.csv` from bitcoin/bips commit
`200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb`:
https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340/test-vectors.csv

SHA-256: `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d`.
Original authors: Pieter Wuille, Jonas Nick and Tim Ruffing. The pinned
[BIP-340 specification](https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340.mediawiki)
is licensed BSD-2-Clause. See LICENSE. Public synthetic secret columns are
TEST-ONLY; never use them for deployment.

All original expected results and messages remain unchanged, including valid
indices 15–18 (0, 1, 17, 100 bytes). The independent oracle verifies all 19.
The pinned production dependency supports original 32-byte messages only:
its four capability observations remain official_expected=true,
supported_by_fixed32_dependency=false, observed_verify=false. These observations
are neither passing production vectors nor invalid BIP-340 vectors.

The upstream file uses CRLF. Its scoped `.gitattributes` entry disables text
conversion and recognizes CR-at-EOL for whitespace checks; the SHA-256 pin
still rejects every byte change. Do not normalize or regenerate this file.
