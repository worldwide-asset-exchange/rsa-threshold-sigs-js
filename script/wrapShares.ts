// script/wrapShares.ts — dealer step of the key ceremony (docs/KEY-CEREMONY.md §5.4).
//
// Reads generatedKeys/threshold-keys.json (generateKey.ts output) and
// generatedKeys/members.json ([{ "index": i, "account": "<member>", "wrappingPublicKey": "<hex>" }]).
// Order: (1) every structural check, (2) verifyShareConsistency on every share, (3) only then
// an EPHEMERAL dealer secp256k1 key (memory only, zeroed on every exit path), wrap share i to
// member i with KeyEncryption and write generatedKeys/member-<i>-<account>.json plus
// generatedKeys/public-package.json. Nothing is written until everything verified, and no
// share (not even a prefix) is ever printed. Needs the optional `secp256k1` peer dependency.
import crypto from "crypto";
import fs from "fs";
import path from "path";
import secp256k1 from "secp256k1";
import { verifyShareConsistency } from "../src";
import { KeyEncryption } from "../src/key-encryption";

type Member = { index: number; account: string; wrappingPublicKey: string };

const EXPECTED = {
  threshold: parseInt(process.env.EXPECTED_THRESHOLD || "2"),
  numParties: parseInt(process.env.EXPECTED_PARTIES || "3"),
  bits: parseInt(process.env.EXPECTED_BITS || "4096"),
};
const HEX = /^[0-9a-f]+$/;
const PUBKEY = /^(04[0-9a-f]{128}|0[23][0-9a-f]{64})$/;
const ACCOUNT = /^[a-z1-5.]{1,12}$/;

const dir = path.join(__dirname, "../generatedKeys");
const keys = JSON.parse(
  fs.readFileSync(path.join(dir, "threshold-keys.json"), "utf8")
);
const members: Member[] = JSON.parse(
  fs.readFileSync(path.join(dir, "members.json"), "utf8")
);

// (1) Structural checks — name-only errors, never a value.
if (
  keys.privateKey !== undefined ||
  keys.p !== undefined ||
  keys.q !== undefined ||
  keys.d !== undefined
) {
  throw new Error(
    "refusing: threshold-keys.json contains the unshared private key (generated with --unsafe-write-private-key); abort the ceremony"
  );
}
for (const field of ["threshold", "numParties", "bits"] as const) {
  if (keys[field] !== EXPECTED[field])
    throw new Error(
      `${field} in threshold-keys.json differs from EXPECTED_${
        field === "numParties" ? "PARTIES" : field.toUpperCase()
      }`
    );
}
const { publicKey, sharedKey, bits, threshold, numParties } = keys;
if (!HEX.test(publicKey.n) || publicKey.n.length !== bits / 4)
  throw new Error(
    "publicKey.n is not lower-case hex of exactly bits/4 digits (setpubkey would reject it)"
  );
if (!HEX.test(publicKey.e))
  throw new Error("publicKey.e is not lower-case hex");
if (!HEX.test(sharedKey.v))
  throw new Error("sharedKey.v is not lower-case hex");
if (!HEX.test(sharedKey.vku))
  throw new Error("sharedKey.vku is not lower-case hex");
if (!Array.isArray(sharedKey.shares) || sharedKey.shares.length !== numParties)
  throw new Error(`sharedKey.shares must have ${numParties} entries`);
if (
  !Array.isArray(sharedKey.verificationKeys) ||
  sharedKey.verificationKeys.length !== numParties
)
  throw new Error(`sharedKey.verificationKeys must have ${numParties} entries`);
for (let i = 1; i <= numParties; i++) {
  if (
    typeof sharedKey.shares[i - 1] !== "string" ||
    !HEX.test(sharedKey.shares[i - 1])
  )
    throw new Error(`share ${i} is not lower-case hex`);
  if (
    typeof sharedKey.verificationKeys[i - 1] !== "string" ||
    !HEX.test(sharedKey.verificationKeys[i - 1])
  )
    throw new Error(`verificationKeys[${i - 1}] is not lower-case hex`);
}
if (!Array.isArray(members) || members.length !== numParties)
  throw new Error(`members.json must list exactly ${numParties} members`);
const seenIndex = new Set<number>();
const seenKey = new Set<string>();
for (const m of members) {
  const where = `members.json entry ${JSON.stringify({
    index: m.index,
    account: m.account,
  })}`;
  if (!Number.isInteger(m.index) || m.index < 1 || m.index > numParties)
    throw new Error(`${where}: index must be an integer in 1..${numParties}`);
  if (seenIndex.has(m.index)) throw new Error(`${where}: duplicate index`);
  if (typeof m.account !== "string" || !ACCOUNT.test(m.account))
    throw new Error(`${where}: account is not a valid WAX account name`);
  if (
    typeof m.wrappingPublicKey !== "string" ||
    !PUBKEY.test(m.wrappingPublicKey) ||
    !secp256k1.publicKeyVerify(Buffer.from(m.wrappingPublicKey, "hex"))
  ) {
    throw new Error(
      `${where}: wrappingPublicKey is not a valid secp256k1 public key (65-byte 04… or 33-byte 02/03… lower-case hex)`
    );
  }
  if (seenKey.has(m.wrappingPublicKey))
    throw new Error(
      `${where}: wrappingPublicKey is also used by another member (two members with one key collapse the threshold)`
    );
  seenIndex.add(m.index);
  seenKey.add(m.wrappingPublicKey);
}

// (2) Share ↔ index ↔ public key binding, for every share, before anything else happens.
for (let i = 1; i <= numParties; i++) {
  try {
    verifyShareConsistency(
      {
        bits,
        sharedKey: sharedKey.shares[i - 1],
        publicKey,
        verificationKey: sharedKey.v,
        verificationKeyShare: sharedKey.verificationKeys[i - 1],
        vku: sharedKey.vku,
      },
      {
        shareIndex: i,
        numParties,
        threshold,
        verificationKeys: sharedKey.verificationKeys,
        expectedPublicKey: publicKey,
      }
    );
  } catch (e) {
    throw new Error(
      `share ${i} failed verifyShareConsistency (${
        (e as Error).name
      }); abort the ceremony`
    );
  }
  console.log(`share ${i}: consistency OK`);
}

// (3) Wrap and write. The dealer wrapping key lives only inside this block.
const fingerprint = crypto
  .createHash("sha256")
  .update(publicKey.n)
  .digest("hex");
const write = (name: string, data: object) => {
  const file = path.join(dir, name);
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", {
    flag: "wx",
    mode: 0o600,
  }); // create-only
  console.log(`wrote ${file}`);
};
let dealerPriv = Buffer.alloc(0);
try {
  do {
    dealerPriv = crypto.randomBytes(32);
  } while (!secp256k1.privateKeyVerify(dealerPriv));
  const dealerWrappingPublicKey = Buffer.from(
    secp256k1.publicKeyCreate(dealerPriv, false)
  ).toString("hex");
  const publicPackage = {
    publicKey,
    bits,
    threshold,
    numParties,
    v: sharedKey.v,
    vku: sharedKey.vku,
    verificationKeys: sharedKey.verificationKeys,
    fingerprint,
    dealerWrappingPublicKey,
    members: [...members]
      .sort((a, b) => a.index - b.index)
      .map(({ index, account }) => ({ index, account })),
    generatedAt: new Date().toISOString(),
  };
  for (const m of members) {
    const i = m.index;
    let kx: KeyEncryption | null = new KeyEncryption(
      dealerPriv,
      Buffer.from(m.wrappingPublicKey, "hex")
    );
    const wrappedShare = kx.encrypt(sharedKey.shares[i - 1]);
    (kx as any)._encryptionKey?.fill(0); // derived AES key; not part of the public API
    kx = null;
    write(`member-${i}-${m.account}.json`, {
      account: m.account,
      shareIndex: i,
      wrappedShare,
      verificationKeyShare: sharedKey.verificationKeys[i - 1],
      ...publicPackage,
    });
    console.log(
      `share ${i} -> ${m.account}: wrapped to key sha256 ${crypto
        .createHash("sha256")
        .update(m.wrappingPublicKey)
        .digest("hex")
        .slice(0, 16)}…`
    );
  }
  write("public-package.json", publicPackage);
} finally {
  dealerPriv.fill(0);
}
console.log(`fingerprint sha256(n) = ${fingerprint}`);
console.log(
  "Dealer wrapping private key was memory-only and is gone. Now destroy threshold-keys.json."
);
