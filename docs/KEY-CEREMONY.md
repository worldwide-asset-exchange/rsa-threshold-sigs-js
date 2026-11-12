# Key ceremony — producing an `orng.wax` key version

This runbook produces one new key version for the `orng.wax` 2-of-3 threshold-RSA oracle:
the public key the producers will install with `setpubkey`, and the three private key shares
the members will sign with. It is written against the `@waxio/rsa-threshold-signatures` **2.0.0**
API (members install that version from npm; the dealer checks out the first tag that ships
`script/wrapShares.ts`, see 5.2), contract `orng.wax` **v3.4.0** and the member process described in the
`wax-rng-oracle` operator guide (sections 2–3, 6.2). The governance runbook in `wax-orng`
(sections 4.2, 5.1, 5.2) decides _when_ the result goes on chain; this document decides _how_
it is made and verified.

Every command below was run as written with throwaway material: the whole flow (sections 4,
5.3–5.5, 7) at 1024 bits, and `generateKeyPair` + `splitShares(2, 3)` once at 4096 bits for the
timing in 5.3. Placeholders are in angle brackets. Nothing in this document is a real key, share
or fingerprint.

## 1. Roles and trust

The scheme is Shoup's threshold RSA with a **trusted dealer**. One `generateKey` run produces
the modulus `n`, the verification keys `v` and `u`, all N shares `s_1..s_N` and their
verification keys `v_1..v_N`; during that run the dealer process holds the whole, unshared
private key (`p`, `q`, `d`) in memory. There is no distributed key generation and no resharing:
the only thing standing between "the dealer could sign alone" and "nobody can" is the procedure
below — an offline machine, witnesses, destruction, and signed attestations. Follow it exactly,
or do not run the ceremony.

| Role                           | Who                                                          | Does                                                                                             |
| ------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| **Ceremony operator** (dealer) | one person, appointed by the producers                       | section 5: generates, verifies, wraps, destroys                                                  |
| **Member operators** (N = 3)   | one per `oracles.a` member                                   | section 4 before, section 7 after: wrapping key, unwrap, verify, stage                           |
| **Witnesses** (2)              | not the dealer, not a member; at least one from a producer   | watch every step of section 5, sign the attestation (5.8)                                        |
| **Governance**                 | whoever proposes the `eosio.msig` transaction for `orng.wax` | section 3 before (indices, version, appointments), section 6 after (`setpubkey` per runbook 5.x) |

## 2. Parameters

| Parameter       | Value for `orng.wax`                                    | Where it is enforced                                                                               |
| --------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `RSA_BITS`      | `4096`                                                  | `ThresholdRSAKey` asserts `n.bitLength() == bits`; members' boot check requires the on-chain width |
| `THRESHOLD` (k) | `2`                                                     | `SHARE_KEY_THRESHOLD` on every member; the contract delivers once 2 partials are on chain          |
| `NUM_PARTIES`   | `3`                                                     | `SHARE_KEY_NUM_PARTIES`; must equal the number of `oracles.a` rows                                 |
| `e`             | `65537` (`RSA_EXPONENT` default; stored as hex `10001`) | Shoup requires a prime `e > N`; `setpubkey` stores whatever string it is given — pass `"10001"`    |
| Share index `i` | 1-based position in the `setoracles` list               | the contract stamps `oracle_index` on partials; the member sets `SHARE_KEY_SHARE_INDEX=<i>`        |

**Who decides the indices:** governance, _before_ the ceremony, as the ordered member list it
will pass to `setoracles` (or the current `oracles.a` order for a same-member rotation). The
dealer deals share `i` to the member at position `i` and nothing else; a member whose
`SHARE_KEY_SHARE_INDEX` differs from its `oracle_index` fails its boot check
(`ORACLE_INDEX_MISMATCH`).

## 3. Before the ceremony (governance)

- [ ] Fix the ordered member list `[<member_1>, <member_2>, <member_3>]`; tell each member its index.
- [ ] Read the version to propose: `pubkeys` rows and `config.a[activever]`
      (`setpubkey` requires `version == highest existing ver + 1`, or `1` on an empty table).
- [ ] Appoint the ceremony operator and two witnesses; agree date, place and the hand-over channels (section 6).
- [ ] Pick the sequence that will follow: governance runbook 5.1 (member change) or 5.2 (same members).

## 4. Member preparation

Each member generates a **fresh** secp256k1 key pair for share wrapping — not the WAX account
key, not reused from an earlier ceremony. `KeyEncryption` takes raw 32-byte private keys and
accepts the public key as 65-byte uncompressed (`04…`, 130 hex chars) or 33-byte compressed
(`02`/`03…`, 66 hex chars); send the uncompressed form, which is what the library tests use.

On an offline machine, in an empty directory: install
`npm install @waxio/rsa-threshold-signatures@2.0.2 secp256k1@5` (on 2.0.0 add `tslib` to that line; it was missing from the package's dependencies) while online (section 7 needs
both), then disconnect, then generate `wrap.key`:

```bash
node -e '
const secp = require("secp256k1"), crypto = require("crypto"), fs = require("fs");
let priv; do { priv = crypto.randomBytes(32); } while (!secp.privateKeyVerify(priv));
fs.writeFileSync("wrap.key", priv.toString("hex"), { mode: 0o600 });
console.log(Buffer.from(secp.publicKeyCreate(priv, false)).toString("hex"));' > wrap.pub
```

Send the dealer, over any authenticated channel (signed e-mail, the producers' chat, a
ticket): the contents of `wrap.pub`, your member account name, and your agreed index. Confirm
the public key's first and last 8 hex characters with the dealer over a second channel (voice
or a different messaging system). `wrap.key` stays on the offline machine until section 7; it
is never sent anywhere.

## 5. Dealer session

Everything in this section happens in one sitting, with both witnesses watching the screen.

### 5.1 Machine

A machine with no persistent state you intend to keep: a freshly installed OS or a live image
booted from read-only media, Node.js 20, and no network once step 5.3 starts. Prepare the
repository while still online, then disconnect (pull the cable / disable the radio) before
generating anything.

### 5.2 Pin the library and install from the lockfile

```bash
git clone https://github.com/worldwide-asset-exchange/rsa-threshold-sigs-js.git
cd rsa-threshold-sigs-js
git checkout <tag>        # the first tag that contains script/wrapShares.ts (v2.0.1 or later)
git rev-parse HEAD        # compare with the commit shown on that tag's release page
yarn install --frozen-lockfile   # installs secp256k1 + ts-node and builds dist/
```

`script/wrapShares.ts` is not in `v2.0.0`; `v2.0.1` is the first tag that ships it.
Witnesses record the exact tag and commit hash — both go into the attestation (5.8). Now
disconnect from the network.

### 5.3 Generate

```bash
RSA_BITS=4096 THRESHOLD=2 NUM_PARTIES=3 yarn ts-node script/generateKey.ts
```

Safe-prime generation at 4096 bits is a random search: one 4096-bit `generateKeyPair` +
`splitShares(2, 3)` took 32 s on the test machine, but the time varies widely from run to run
and between machines — do not treat a slow run as a fault. The script refuses to overwrite
an existing `generatedKeys/threshold-keys.json`, writes the file create-only with mode `0600`,
and does **not** write the unshared private key (never pass `--unsafe-write-private-key`). The
console shows `n` in full and the share count; nothing it prints is secret. Output file shape
(every value is lower-case hex, unpadded `toString(16)` — shares and `v_i` may be a digit shorter
than `n`, which the library parses fine):

```json
{
  "publicKey": {
    "n": "<4096-bit modulus, exactly 1024 hex chars>",
    "e": "10001"
  },
  "sharedKey": {
    "shares": ["<s_1>", "<s_2>", "<s_3>"],
    "v": "<v>",
    "vku": "<u>",
    "verificationKeys": ["<v_1>", "<v_2>", "<v_3>"]
  },
  "bits": 4096,
  "threshold": 2,
  "numParties": 3
}
```

`sharedKey.shares` is the secret. The rest is public.

### 5.4 Verify, wrap and package

Write `generatedKeys/members.json` from the public keys received in section 4, in index order:

```json
[
  {
    "index": 1,
    "account": "<member_1>",
    "wrappingPublicKey": "<04… hex from member 1>"
  },
  {
    "index": 2,
    "account": "<member_2>",
    "wrappingPublicKey": "<04… hex from member 2>"
  },
  {
    "index": 3,
    "account": "<member_3>",
    "wrappingPublicKey": "<04… hex from member 3>"
  }
]
```

Read each `wrappingPublicKey` back to the witnesses against what the member confirmed over the
second channel. Then:

```bash
yarn ts-node script/wrapShares.ts
```

`script/wrapShares.ts` uses the library's public API (`verifyShareConsistency`) plus the
explicitly imported dealer helper `src/key-encryption` (published as `dist/key-encryption`,
deliberately not an index export). It writes nothing until every check has passed, and never
prints a share or any part of one. In order:

1. **Checks.** Refuses a `threshold-keys.json` that contains the unshared private key
   (`--unsafe-write-private-key` was used); requires `threshold` / `numParties` / `bits` to equal
   `EXPECTED_THRESHOLD` / `EXPECTED_PARTIES` / `EXPECTED_BITS` (defaults `2` / `3` / `4096`);
   requires `n` to be lower-case hex of exactly `bits/4` digits (what `setpubkey` accepts) and
   every share, `v_i`, `v`, `u` to be lower-case hex (name-only errors such as
   `share 2 is not lower-case hex`); requires `members.json` to list exactly `numParties`
   entries with distinct integer indices in `1..numParties`, valid account names, and distinct,
   valid secp256k1 wrapping public keys (two members behind one key would collapse the threshold).
2. **Binding.** For every share `i`, `verifyShareConsistency` with
   `{ shareIndex: i, numParties, threshold, verificationKeys, expectedPublicKey }` — the same
   call the member runs in section 7. A failure is reported as
   `share <i> failed verifyShareConsistency (<error class>)` and the ceremony stops. Note what
   this proves: share `i` ↔ `v_i` ↔ index ↔ _this_ public package fit together. It does not say
   the package is the one governance will install — that is the fingerprint comparison (5.5, 7).
3. **Wrap and write.** Generates an **ephemeral** dealer secp256k1 key in memory (zeroed on every
   exit path, never written — no one, including the dealer, can unwrap a share after the process
   exits); wraps share `i` with `new KeyEncryption(<dealer private>, <member i public>).encrypt(s_i)`
   (ECDH secp256k1 → SHA-256 → AES-256-GCM; payload `<ciphertext>:<iv>:<authTag>`, three hex
   fields), drops the instance; writes `generatedKeys/member-<i>-<account>.json` and
   `generatedKeys/public-package.json` create-only with mode `0600`; prints the fingerprint and,
   per member, the sha256 of the wrapping key it used (first 16 hex) for the witnesses.

Per-member file (`member-<i>-<account>.json`, mode `0600`, contains no plaintext share):

```json
{
  "account": "<member_i>",
  "shareIndex": i,
  "wrappedShare": "<ciphertext>:<iv>:<authTag>",
  "verificationKeyShare": "<v_i>",
  "publicKey": { "n": "<n>", "e": "10001" },
  "bits": 4096,
  "threshold": 2,
  "numParties": 3,
  "v": "<v>",
  "vku": "<u>",
  "verificationKeys": ["<v_1>", "<v_2>", "<v_3>"],
  "fingerprint": "<sha256 of n, 64 hex chars>",
  "dealerWrappingPublicKey": "<04… 130 hex chars>",
  "members": [{ "index": 1, "account": "<member_1>" }, { "index": 2, "account": "<member_2>" }, { "index": 3, "account": "<member_3>" }],
  "generatedAt": "<ISO-8601>"
}
```

`public-package.json` is the same object without `account`, `shareIndex`, `wrappedShare` and
`verificationKeyShare`. The dealer wrapping public key is needed by every member for the ECDH
unwrap; it is public.

Optional but recommended before destruction — prove the set actually signs (sign with shares 1
and 2, combine, verify with plain Node RSA against the public key; must print
`node crypto.verify: true`):

```bash
node -e '
const { ThresholdRSAShare, ThresholdRSAVerifier } = require("./dist");
const crypto = require("crypto"), k = require("./generatedKeys/threshold-keys.json");
const msg = Buffer.from("key-ceremony smoke test");
const parts = [1, 2].map(i => ({ shareIndex: i, signatureShare: new ThresholdRSAShare({ bits: k.bits, sharedKey: k.sharedKey.shares[i-1], publicKey: k.publicKey, verificationKey: k.sharedKey.v, verificationKeyShare: k.sharedKey.verificationKeys[i-1], vku: k.sharedKey.vku }).signMessage(msg).signatureShare }));
const { signature, usedShareIndices } = new ThresholdRSAVerifier({ threshold: k.threshold, numParties: k.numParties, bits: k.bits, publicKey: k.publicKey, verificationKey: k.sharedKey.v, vku: k.sharedKey.vku, verificationKeys: k.sharedKey.verificationKeys }).combineSignatureMessage(msg, parts);
const pub = crypto.createPublicKey({ key: { kty: "RSA", n: Buffer.from(k.publicKey.n, "hex").toString("base64url"), e: Buffer.from(k.publicKey.e.padStart(6, "0"), "hex").toString("base64url") }, format: "jwk" });
console.log("used", usedShareIndices, "sig width", signature.length, "== bits/4", signature.length === k.bits / 4, "node crypto.verify:", crypto.verify("sha256", msg, pub, Buffer.from(signature, "hex")));'
```

### 5.5 Fingerprint

The fingerprint is `sha256` of the lower-case hex modulus **as a string** — exactly the string
`setpubkey` will store in `pubkeys[ver].modulus`, so the same command run against the chain row
must give the same digest (governance runbook 4.2, operator guide 2.4). Compute it twice, two ways,
and have a witness read all 64 characters aloud:

```bash
node -e 'process.stdout.write(require("./generatedKeys/public-package.json").publicKey.n)' | sha256sum
node -e 'const p = require("./generatedKeys/public-package.json"); console.log(require("crypto").createHash("sha256").update(p.publicKey.n).digest("hex") === p.fingerprint ? p.fingerprint : "MISMATCH")'
```

### 5.6 Copy out

Copy to removable media, and nothing else: `public-package.json` and the three
`member-<i>-<account>.json` files. `threshold-keys.json` and `members.json` stay on the machine.
Witnesses confirm the file list on the media.

### 5.7 Destroy

With witnesses watching, in this order:

```bash
cd .. && find rsa-threshold-sigs-js/generatedKeys -type f -exec shred -u -n 3 {} \; && rm -rf rsa-threshold-sigs-js
```

then power the machine off, and wipe or physically destroy its storage (a live image with no
writable disk satisfies this by powering off). The dealer's wrapping private key never existed
on disk; the unshared private key never existed on disk; the plaintext shares are now gone.

### 5.8 Attestation

Both witnesses and the dealer sign (hand-written or PGP) a statement with at least:

```
orng.wax key ceremony attestation
library:        @waxio/rsa-threshold-signatures <tag>, commit <sha>
parameters:     bits 4096, threshold 2, numParties 3, e 10001
members/index:  1 <member_1>  2 <member_2>  3 <member_3>
fingerprint:    <64 hex chars>
version to propose: <ver>
started / finished: <ISO-8601> / <ISO-8601>, <place>
consistency check: passed for shares 1, 2, 3   smoke test: passed / not run
destruction:    shred + power-off + <wipe/destroy method> witnessed at <time>
signatures:     <dealer>  <witness 1>  <witness 2>
```

The attestation is public; publish it where the producers publish governance material.

## 6. Hand-over

| To         | What                                                                                                                 | Channel                                                                              |
| ---------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| member `i` | `member-<i>-<account>.json` (wrapped share, index, public package, fingerprint, dealer wrapping public key)          | any channel — only `wrap.key` can open it, and GCM rejects tampering                 |
| member `i` | the fingerprint                                                                                                      | a **second, independent** channel (voice, signed message, the published attestation) |
| governance | `public-package.json` (`e`, `n`, fingerprint, members, parameters) + the version number to propose + the attestation | the channel the msig proposer will quote in the proposal                             |

Governance builds the proposal from `public-package.json`:
`setpubkey '{"version":<ver>,"exponent":"10001","modulus":"<publicKey.n>"}'` and verifies, before
proposing, that `printf '%s' "<modulus from the proposal>" | sha256sum` equals the attestation
fingerprint.

## 7. Member verification and staging

On the offline machine from section 4, with `wrap.key`, the received `member.json`, and
`npm install @waxio/rsa-threshold-signatures@2.0.2 secp256k1@5` (on 2.0.0 add `tslib` to that line; it was missing from the package's dependencies) done (online, before the file is
brought over). Unwrap:

```bash
node -e '
const { KeyEncryption } = require("@waxio/rsa-threshold-signatures/dist/key-encryption");
const fs = require("fs"), m = JSON.parse(fs.readFileSync("member.json", "utf8"));
const kx = new KeyEncryption(Buffer.from(fs.readFileSync("wrap.key", "utf8").trim(), "hex"),
                             Buffer.from(m.dealerWrappingPublicKey, "hex"));
fs.writeFileSync("share.hex", kx.decrypt(m.wrappedShare), { mode: 0o600 });
console.log("unwrapped", fs.statSync("share.hex").size, "hex chars");'
```

A wrong `wrap.key`, wrong dealer key or altered payload throws (`Unsupported state or unable to authenticate data`) rather than producing a wrong share. Then check the share against the public
package — the same call the dealer ran:

```bash
node -e '
const { verifyShareConsistency } = require("@waxio/rsa-threshold-signatures");
const fs = require("fs"), crypto = require("crypto"), m = JSON.parse(fs.readFileSync("member.json", "utf8"));
const r = verifyShareConsistency(
  { bits: m.bits, sharedKey: fs.readFileSync("share.hex", "utf8"), publicKey: m.publicKey,
    verificationKey: m.v, verificationKeyShare: m.verificationKeyShare, vku: m.vku },
  { shareIndex: m.shareIndex, numParties: m.numParties, threshold: m.threshold,
    verificationKeys: m.verificationKeys, expectedPublicKey: m.publicKey });
const fp = crypto.createHash("sha256").update(r.modulusHex).digest("hex");
console.log("consistency ok:", r.ok, "index", r.shareIndex, "fingerprint", fp, "matches package:", fp === m.fingerprint);'
```

Expected: `consistency ok: true index <i> fingerprint <64 hex> matches package: true`. Be
clear about what that proves: `expectedPublicKey` came from the same `member.json`, so the check
binds your share ↔ `v_i` ↔ index ↔ _this_ package and nothing more. The independent check is the
fingerprint: compare it, character by character, with (a) the one received over the second
channel, (b) the attestation, and (c) the `modulus` in governance's `setpubkey` proposal once it
exists (`printf '%s' "<modulus>" | sha256sum`). (The member process repeats the consistency check
at boot, but against the on-chain `pubkeys[activever]` row — that is what finally ties your share
to the installed key.) Confirm `m.shareIndex` equals your agreed index and your position in
`m.members`.

Configure the member process from the file. The environment variables and their meaning are in
the operator guide
([§2.3](https://github.com/worldwide-asset-exchange/wax-rng-oracle/blob/main/docs/OPERATOR-GUIDE.md)
and Appendix A), written in terms of the `generateKey.ts` output layout; `member.json` flattens
that layout:

| `member.json` field                | `generateKey.ts` field (operator guide 2.3) |
| ---------------------------------- | ------------------------------------------- |
| `share.hex` (your unwrapped share) | `sharedKey.shares[i-1]`                     |
| `verificationKeyShare`             | `sharedKey.verificationKeys[i-1]`           |
| `v`                                | `sharedKey.v`                               |
| `vku`                              | `sharedKey.vku`                             |
| `publicKey.n` / `publicKey.e`      | `publicKey.n` / `publicKey.e`               |
| `bits`, `threshold`, `numParties`  | same names                                  |
| `shareIndex`                       | your index `i`                              |

**Stage and start now.** Write a **second** environment file next to the live one (operator
guide 3.1; a continuing member never overwrites the file its old process restarts from) and
start the new process from it (operator guide 6.2). The chain still carries the old version, so the boot check fails
— `ORACLE_NOT_REGISTERED` for a new member, `ORACLE_INDEX_MISMATCH` or `expectedPublicKey` for a
continuing one — the process exits and systemd restarts it every few seconds. That is the
expected state: it signs nothing until governance executes the switch (runbook 5.1 / 5.2), after
which the next restart passes by itself; nobody has to be at a keyboard at switch time. A
continuing member runs the new process beside the old one and stops the old one afterwards.
Keep `wrap.key` plus `member.json` offline as the backup of your share; delete `share.hex` from
anywhere but the environment file.

## 8. First ceremony vs rotation

|                 | First key on a chain                    | Rotation (`pubkeys` already has rows)                                                                                |
| --------------- | --------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Version         | `1`                                     | highest existing `ver + 1` (`setpubkey` rejects anything else); never reuse a modulus (`"public key already exist"`) |
| Indices         | the `setoracles` order governance chose | unchanged for 5.2; new list order for 5.1 — continuing members keep their position where possible                    |
| Wrapping keys   | fresh                                   | fresh again; never reuse a `wrap.key`                                                                                |
| Members' action | configure (operator guide 3) and start  | stage the new environment and start beside the old process; it goes live at the switch (guide 6.2)                   |
| Old key         | —                                       | `retirepubkey(<old ver>)` after the switch; old `share.hex` / environment files are then destroyed by each member    |

Everything else in sections 4–7 is identical. A rotation is also the only remedy for a lost or
suspected-compromised share: there is no resharing, so one bad share means a whole new key.

## 9. Abort rules

Any of the following stops the ceremony; the result is reported to governance and a **new
ceremony** is scheduled. Nobody edits, re-derives or "repairs" a share, a verification key or
a public package — a hand-fixed value that passes a check is exactly how a bad key gets installed.

- `git rev-parse HEAD` does not match the release commit, or `yarn install --frozen-lockfile` fails.
- `generateKey.ts` or `wrapShares.ts` exits non-zero (a refused private key, a parameter or hex check, a `members.json` rejection, `verifyShareConsistency`, an existing output file).
- The two fingerprint computations disagree, or a member's / governance's fingerprint differs from the attestation.
- A member's unwrap throws, `consistency ok` is `false`, or `index` is not the agreed one.
- The network was reconnected, a file left the machine that is not in 5.6, or a witness was absent for any step.
- The dealer passed `--unsafe-write-private-key`.

## 10. Checklist

| Step                                                                   | Dealer | Member | Witness | Governance |
| ---------------------------------------------------------------------- | :----: | :----: | :-----: | :--------: |
| Ordered member list + indices fixed                                    |        |   ✓    |         |     ✓      |
| Version to propose read from chain                                     |        |        |         |     ✓      |
| Dealer + witnesses appointed                                           |        |        |    ✓    |     ✓      |
| Fresh `wrap.key` / `wrap.pub` made (4)                                 |        |   ✓    |         |            |
| `wrap.pub` + account + index sent, confirmed on 2nd channel            |   ✓    |   ✓    |         |            |
| Clean machine, repo at the pinned tag, tag + commit recorded (5.1–5.2) |   ✓    |        |    ✓    |            |
| Network disconnected                                                   |   ✓    |        |    ✓    |            |
| `generateKey.ts` run with 4096 / 2 / 3 (5.3)                           |   ✓    |        |    ✓    |            |
| `members.json` read back against confirmed keys (5.4)                  |   ✓    |        |    ✓    |            |
| `wrapShares.ts` passed for shares 1–3 (5.4)                            |   ✓    |        |    ✓    |            |
| Smoke test `crypto.verify: true` (optional)                            |   ✓    |        |    ✓    |            |
| Fingerprint computed twice, read aloud (5.5)                           |   ✓    |        |    ✓    |            |
| Only package + member files copied out (5.6)                           |   ✓    |        |    ✓    |            |
| Shred, power-off, wipe (5.7)                                           |   ✓    |        |    ✓    |            |
| Attestation signed and published (5.8)                                 |   ✓    |        |    ✓    |     ✓      |
| Member file + fingerprint (2nd channel) delivered (6)                  |   ✓    |   ✓    |         |            |
| Unwrap OK, consistency OK, index OK (7)                                |        |   ✓    |         |            |
| Fingerprint = attestation = proposal modulus (7)                       |        |   ✓    |         |     ✓      |
| New environment staged and started, crash-looping as expected (7)      |        |   ✓    |         |            |
| `setpubkey` proposed from `public-package.json` (6)                    |        |        |         |     ✓      |
| Pause / drain / switch / retire per runbook 5.1–5.2                    |        |        |         |     ✓      |
| Rotation only: old process stopped after the switch (7, 8)             |        |   ✓    |         |            |
| Old shares and environment files destroyed (8)                         |        |   ✓    |         |            |
