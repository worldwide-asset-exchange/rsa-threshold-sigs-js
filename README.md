# RSA Threshold signatures library

A JavaScript implementation of threshold RSA signatures based on [Victor Shoup's "Practical Threshold Signatures" (Eurocrypt 2000)](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf).

`l` parties each hold a share `s_i` of an RSA private key; any `k` of them can
produce a standard RSASSA-PKCS1-v1_5 / SHA-256 signature that verifies under the
public key `(n, e)` with any RSA implementation. See [CHANGELOG.md](CHANGELOG.md)
for release notes.

### Install

```bash
$ yarn add @waxio/rsa-threshold-signatures   # runtime dependency: node-forge only
```

### Usage

```ts
import {
  ThresholdRSAShare,
  ThresholdRSAVerifier,
  verifyShareConsistency,
} from "@waxio/rsa-threshold-signatures";

// Party i (1-based shareIndex). All values are hex strings or jsbn BigIntegers.
const config = {
  bits,
  sharedKey,
  publicKey: { n, e },
  verificationKey: v,
  verificationKeyShare: v_i,
  vku: u,
};

// Boot-time self-check: fails loudly if the share, its verification key, the
// index, the modulus width or the exponent do not fit together.
verifyShareConsistency(config, {
  shareIndex,
  numParties,
  threshold,
  verificationKeys, // dealer-published v_1..v_l
  expectedPublicKey: { n: onChainModulus, e: onChainExponent },
});

const share = new ThresholdRSAShare(config);
const { signatureShare } = share.signMessage(messageBytes); // partial x_i, a BigInteger < n

// Combiner
const verifier = new ThresholdRSAVerifier({
  threshold,
  numParties,
  bits,
  publicKey: { n, e },
  verificationKey: v,
  vku: u,
  verificationKeys,
});
const result = verifier.combineSignatureMessage(messageBytes, [
  { shareIndex: 1, signatureShare: x_1 },
  { shareIndex: 2, signatureShare: x_2 },
  { shareIndex: 3, signatureShare: x_3 },
]);
result.signature; // lower-case hex, exactly bits/4 characters, < n — a standard RSA signature
result.usedShareIndices; // the k-subset that verified, e.g. [1, 2]
result.suspectShareIndices; // indices that only appeared in failed subsets
```

`verifySignatureMessage` / `verifySignatureHash` return just the signature string
(unchanged API). Both throw `CombineError` (`code`: `NOT_ENOUGH_SHARES`,
`INVALID_SHARE`, `NO_VALID_SUBSET`) naming the offending share index(es).

#### Behaviour guarantees (relied on by the on-chain verifier)

- The combined signature is **lower-case hex, exactly `bits/4` wide and `< n`**,
  deterministic for a given key and message, and identical for every `k`-subset.
  Leading-zero padding is normal (~1/16 of signatures start with `0`).
- Partial signatures are plain integers in `(0, n)` (unpadded in `toString(16)`).
- Every partial is checked to be in `(0, n)` and coprime to `n` before the combine;
  the combine tries `k`-subsets of the valid partials until one verifies.
- All hex input is parsed strictly (`[0-9a-fA-F]+`, either case, any length).
  Strings are hex: a decimal `"65537"` is read as `0x65537`.
- `bits` must equal `n.bitLength()` (and `bits % 8 == 0`); constructors throw otherwise.

#### Proofs of correctness (off by default)

`signMessage(msg, { proof: true })` attaches Shoup's proof; the verifier checks it
with `verifySharesHash/Message` (boolean) or `verifySharesHashDetailed`
(`{ ok, failures[] }`). Proof verification requires the dealer-published
`verificationKeys` in the verifier config — the prover-supplied
`sharedVerificationKey` field is ignored. Production signing does not use proofs.

### Key ceremony

`script/generateKey.ts` is a **trusted-dealer** ceremony: whoever runs it sees
every share and (in memory) the whole private key. Intended path:

1. Run the dealer on an isolated host:
   `RSA_BITS=4096 THRESHOLD=2 NUM_PARTIES=3 yarn ts-node script/generateKey.ts`
   The output `generatedKeys/threshold-keys.json` (mode 0600) holds the public key,
   `v`, `u`, every party's share and verification key. The unshared private key is
   **not** written unless you pass `--unsafe-write-private-key` (don't).
2. Wrap each share to its party with `KeyEncryption` (ECDH secp256k1 + AES-256-GCM;
   `require('@waxio/rsa-threshold-signatures/dist/key-encryption')`, needs the
   optional `secp256k1` peer dependency) using the party's public key, and hand
   each party only its own wrapped share plus the public parameters.
3. Destroy the dealer output and the dealer host's storage; record the public key
   fingerprint and the destruction step.
4. Each party runs `verifyShareConsistency` on its decrypted share before it signs.

### Sample scripts

```bash
$ yarn ts-node script/generateKey.ts        # dealer (see above)
$ yarn ts-node script/signShare.ts          # self-check, sign, prove, combine, verify with node-rsa
```

### Run tests

```bash
$ yarn test
```

Test fixtures are throwaway keys generated for the tests (`tests/fixtures/`);
`tests/fixtures/golden-1.3.0-*.json` are signatures produced by the published
1.3.0 build that every later version must reproduce byte-for-byte.
