// Canonical-output invariants (contract.md §1 / signing-lib.md §3.1): the combined
// signature is lower-case hex, exactly bits/4 wide, < n, identical for every
// k-subset, and a valid PKCS#1 v1.5 signature under OpenSSL.
import crypto from "crypto";
import { BigInteger, parseBigInteger } from "../src/utils";
import {
  loadThrowawayKey,
  makeSigners,
  makeVerifier,
  opensslVerify,
  partialFor,
} from "./fixtures";

function checkMany(bits: 1024 | 4096, count: number) {
  const fx = loadThrowawayKey(bits);
  const n = parseBigInteger(fx.publicKey.n);
  const signers = makeSigners(fx);
  const verifier = makeVerifier(fx);
  let leadingZero = 0;
  for (let k = 0; k < count; k++) {
    const m = crypto.randomBytes(32); // = make_msg output shape (32 raw bytes)
    const parts = signers.map((s, i) => partialFor(s, i, m));
    const sig = verifier.verifySignatureMessage(m, [parts[0], parts[1]]);
    expect(sig).toBe(sig.toLowerCase());
    expect(sig.length).toBe(bits / 4);
    expect(/^[0-9a-f]+$/.test(sig)).toBe(true);
    expect(new BigInteger(sig, 16).compareTo(n)).toBeLessThan(0);
    expect(verifier.verifySignatureMessage(m, [parts[1], parts[2]])).toBe(sig);
    expect(verifier.verifySignatureMessage(m, [parts[2], parts[0]])).toBe(sig);
    expect(sig.toString()).toBe(sig); // String.prototype.toString is a no-op (poller.js)
    expect(opensslVerify(fx, m, sig)).toBe(true);
    // partials are unpadded integers < n
    for (const p of parts) {
      expect(p.signatureShare.signum()).toBe(1);
      expect(p.signatureShare.compareTo(n)).toBeLessThan(0);
    }
    if (sig[0] === "0") leadingZero++;
  }
  return leadingZero;
}

describe("combined signature canonical form", () => {
  it("1,000 signatures at 1024 bits (leading-zero padding is the normal case, ~1/16)", () => {
    const leadingZero = checkMany(1024, 1000);
    expect(leadingZero).toBeGreaterThan(0);
  });

  it("40 signatures at 4096 bits (production width: 1024 hex chars)", () => {
    checkMany(4096, 40);
  });
});
