# Changelog

All notable changes to `@waxio/rsa-threshold-signatures` are documented here.
Finding IDs (`SIG-n`) refer to the internal 2026-10 security review of the RNG
signing library; the release ticket is WBP-2065.

## 1.4.0 — 2026-10-29

Security-hardening release. For valid inputs, every partial signature and every
combined signature is **bit-identical to 1.3.0** — proven by the golden vectors
in `tests/fixtures/golden-1.3.0-*.json`, generated with the published 1.3.0
build (git `8750c7e`) and replayed against this version in
`tests/golden-1.3.0.test.ts`. The combined signature stays lower-case hex,
exactly `bits/4` characters wide and `< n`; the partial-signature format is
unchanged.

### Combine path (`ThresholdRSAVerifier.verifySignatureHash/Message`)

- **SIG-13** Every partial is checked to be in `(0, n)` and coprime to `n`
  before it is used. A zero (or `≡ 0 mod n`) partial in the negative-Lagrange
  slot used to reach `node-forge`'s `modInverse(0)`, which looped forever on
  `node-forge < 1.4.0` and wedged the calling process. `node-forge` now has a
  `^1.4.0` floor.
- **SIG-4** The combine no longer takes only the first `k` shares: it iterates
  `k`-subsets of the valid shares until one verifies — first the cyclic windows
  of `k` consecutive shares (the first window is the first `k`, so honest input
  behaves as before, and any single bad share is excluded within `l` attempts
  for every `(k, l)`), then the remaining subsets, bounded by
  `maxCombineAttempts` (default 256).
- A share with an out-of-range index or an unparseable value is **rejected and
  skipped** (reported in `rejectedShares`) rather than aborting the combine, so
  `k` good shares still produce a signature; duplicate indices anywhere in the
  set still throw (`DUPLICATE_INDEX`).
- New `combineSignatureHash/Message(...)` return a `CombineResult`
  (`signature`, `usedShareIndices`, `rejectedShares`, `failedSubsets`,
  `suspectShareIndices` = indices present in every failed subset and absent
  from the verified one, `attempts`) so a consumer can attribute a bad
  partial. The string-returning methods are unchanged wrappers.
- Failures throw `CombineError` with `code` (`NOT_ENOUGH_SHARES`,
  `DUPLICATE_INDEX`, `INVALID_SHARE`, `NO_VALID_SUBSET`), `rejectedShares` and
  `attemptedSubsets`;
  messages name the offending share index(es). Legacy messages
  (`Not enough shares…`, `Invalid share index…`, `Duplicate share indices detected`) are preserved.
- `signatureShare` may be passed as a strict hex string as well as a
  `BigInteger`.
- `threshold`, `numParties`, `bits` and `maxCombineAttempts` accept decimal
  strings as well as numbers (consumers read them from env; 1.3.0 relied on
  implicit coercion). Any other string throws a `TypeError` at construction.

### Parsing and self-checks

- **SIG-5** `parseBigInteger` is strict: `[0-9a-fA-F]+` only (either case, any
  length — odd length is fine, the string is an integer). Empty strings,
  whitespace, `0x` prefixes, signs and non-hex characters throw instead of
  being silently skipped by `jsbn`. Strings are still read **as hex**: a
  decimal `"65537"` is `0x65537`; use `verifyShareConsistency` with
  `expectedPublicKey` to catch that.
- **SIG-12** `ThresholdRSAShare`, `ThresholdRSAVerifier` and
  `ThresholdRSAKey.generateKeyPair` assert `n.bitLength() == bits` and
  `bits % 8 == 0` (hence hex width `== bits/4`); share/verifier constructors
  also check every value — including `verificationKeys[]` — is in `(0, n)`
  (and coprime to `n` where that is required).
- New `verifyShareConsistency(config, options)` (also
  `share.verifyConsistency(options)`): the boot-time self-check an oracle
  member should run before signing. Checks `v^{s_i} == v_i`, `J(u|n) = −1`,
  `J(v|n) = +1`, exponent primality and `e > numParties`, share/index ranges,
  `verificationKeys[shareIndex−1] == v_i`, and agreement with an
  `expectedPublicKey` (e.g. the on-chain `pubkeys` row, including modulus hex
  width) and `verificationKeys.length == numParties`. Returns a structured
  `ShareConsistencyResult` and throws
  `ShareConsistencyError` on any failure (`throwOnFailure: false` to get the
  result instead).

### Proof path (`verifySharesHash/Message`) — off by default, unchanged default

- **SIG-1** The verifier takes dealer-published `verificationKeys[]` in its
  config and looks `v_i` up by `shareIndex`; a prover-supplied
  `sharedVerificationKey` is ignored (field deprecated). **Breaking for proof
  verification only:** `verifySharesHash` throws if the verifier was built
  without `verificationKeys`. A silent fallback to the prover's value would
  have kept the forgery open, so this break is deliberate. Combining does not
  need `verificationKeys`.
- **SIG-2** One shared digest encoder (`digestToSigningInteger`) is used by
  sign, combine and proof verification; `verifySharesHash` no longer drops a
  nibble for digests with a leading zero nibble (~1/16 of messages).
- **SIG-11** `hashTranscript` has a domain tag and 4-byte length framing per
  element. Proofs produced by earlier versions do not verify (none are
  persisted anywhere).
- New `verifySharesHashDetailed(...)` returns `{ ok, failures[] }` with the
  failing share index and reason; malformed shares (missing or non-numeric
  proof, negative `z`, `c` wider than 256 bits, bad index, share not in
  `(0, n)`) yield `false` instead of a `TypeError`. `proof.z`/`proof.c` may be
  hex strings.

### Dependency surface

- **SIG-6** `KeyEncryption` no longer accepts the unauthenticated legacy
  2-field AES-256-CBC payload (`LEGACY_ALGORITHM` removed); GCM only.
- **SIG-7** `KeyEncryption` is no longer exported from the package index and
  `secp256k1` moved from `dependencies` to an **optional peer dependency**
  (`dependencies` is now `node-forge` only). The ceremony tooling imports it
  from `@waxio/rsa-threshold-signatures/dist/key-encryption`. The library's
  random bytes come from `node:crypto`; `node-forge` is used only for
  `jsbn.BigInteger`.
- `node-forge` `^1.4.0` (was `^1.3.1`): clears the reachable `modInverse(0)`
  advisory (GHSA-5m6q-g25r-mvwx) and the other forge advisories.

### Signing

- **SIG-8** The secret-share exponentiation `x̃^{2 s_i}` is blinded
  (`blindedModPow`): a random `r ∈ Z_n^*` multiplies the base and `r^{2 s_i}`
  is divided back out, so the exponentiation with the share never runs on a
  requester-chosen input. Output is bit-identical (tested).

### Fixtures and dealer tooling

- **SIG-9** All test fixtures are now throwaway keys generated for the tests
  (`tests/fixtures/throwaway-key-*-2of3.json`, labelled as such); the
  retired-testnet share and the second 4096-bit quorum were removed from the
  test sources, and the "existing CPP implementation" vectors (same key) were
  replaced by the 1.3.0 golden vectors.
- **SIG-3** `script/generateKey.ts` no longer writes the unshared private key
  unless `--unsafe-write-private-key` is passed, prints a warning when it is,
  creates `generatedKeys/` with mode `0700` and the output file create-only
  with mode `0600` (refusing to overwrite a previous ceremony output), and the
  README documents the encrypt-to-party ceremony as the intended path.

### Exports

- `index` now also exports `BigInteger`, `parseBigInteger`, `toCanonicalHex`,
  `verifyShareConsistency`, `ShareConsistencyError`, `CombineError` and the
  new result types.
- Note on versioning: removing `KeyEncryption` from the index and the CBC
  fallback are strictly breaking changes shipped in a minor version because
  the only known consumer (the WAX RNG oracle) uses neither and pins `^1.3.0`;
  the proof-path `verificationKeys` requirement likewise affects no known
  caller.

## 1.3.0 — 2026-05-25

Security hardening from the pre-open-source audit (uniform random sampling,
GCM key wrapping, share-index range and duplicate guards, empty-set guard).
