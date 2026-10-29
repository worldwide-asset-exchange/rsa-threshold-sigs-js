// Invariant (WBP-2065): for valid inputs, 1.4.0 must produce exactly the partial
// and combined signatures that the published 1.3.0 dist produced. The golden
// files were generated against the 1.3.0 build (git 8750c7e) with the throwaway
// fixture keys; see tests/fixtures/*.json `_comment`.
import { BigInteger, parseBigInteger } from "../src/utils";
import {
  decodeMessage,
  loadGolden,
  loadThrowawayKey,
  makeSigners,
  makeVerifier,
  opensslVerify,
} from "./fixtures";

describe.each([1024, 4096] as const)(
  "golden 1.3.0 equivalence (%i bits)",
  (bits) => {
    const fx = loadThrowawayKey(bits);
    const golden = loadGolden(bits);
    const signers = makeSigners(fx);
    const verifier = makeVerifier(fx);
    const n = parseBigInteger(fx.publicKey.n);

    it("golden file was produced by the 1.3.0 reference build", () => {
      expect(golden.generatedBy.version).toBe("1.3.0");
      expect(golden.generatedBy.commit).toBe("8750c7e");
      expect(golden.bits).toBe(bits);
      // Both Jacobi branches and both digest shapes are covered.
      expect(golden.vectors.some((v) => v.lifted)).toBe(true);
      expect(golden.vectors.some((v) => !v.lifted)).toBe(true);
      expect(golden.vectors.some((v) => v.zeroNibble)).toBe(true);
      expect(golden.vectors.some((v) => !v.zeroNibble)).toBe(true);
    });

    it("signMessage reproduces every 1.3.0 partial signature byte-for-byte", () => {
      for (const v of golden.vectors) {
        const message = decodeMessage(v);
        for (let i = 0; i < signers.length; i++) {
          const r = signers[i].signMessage(message);
          expect(r.signatureShare.toString(16)).toBe(v.partials[i]);
          expect(r.proof).toBeUndefined();
          expect(r.msgBigInt.toString(16).padStart(64, "0")).toBe(v.sha256);
        }
      }
    });

    it("combine reproduces every 1.3.0 combined signature for every 2-subset", () => {
      for (const v of golden.vectors) {
        const message = decodeMessage(v);
        const parts = v.partials.map((p, i) => ({
          signatureShare: new BigInteger(p, 16),
          shareIndex: i + 1,
        }));
        for (const subset of [
          [0, 1],
          [0, 2],
          [1, 2],
        ]) {
          const sig = verifier.verifySignatureMessage(
            message,
            subset.map((i) => parts[i])
          );
          expect(sig).toBe(v.combined);
        }
        // canonical form: lower-case, bits/4 wide, < n
        expect(v.combined).toBe(v.combined.toLowerCase());
        expect(v.combined.length).toBe(bits / 4);
        expect(new BigInteger(v.combined, 16).compareTo(n)).toBeLessThan(0);
        // independent PKCS#1 v1.5 check (OpenSSL)
        expect(opensslVerify(fx, message, v.combined)).toBe(true);
      }
    });

    it("signHash/verifySignatureHash with pkcs1=false reproduce the 1.3.0 raw-hash vectors", () => {
      for (const v of golden.vectors.filter((x) => x.rawHashPartials)) {
        for (let i = 0; i < signers.length; i++) {
          const r = signers[i].signHash(v.sha256, {
            pkcs1: false,
            proof: false,
          });
          expect(r.signatureShare.toString(16)).toBe(v.rawHashPartials[i]);
        }
        const sig = verifier.verifySignatureHash(
          v.sha256,
          [0, 1].map((i) => ({
            signatureShare: new BigInteger(v.rawHashPartials[i], 16),
            shareIndex: i + 1,
          })),
          false
        );
        expect(sig).toBe(v.rawHashCombined);
      }
    });
  }
);
