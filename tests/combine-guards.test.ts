// SIG-4 / SIG-13: partial-signature guards and k-subset retry in the combine path.
import crypto from "crypto";
import { CombineError, ThresholdRSAShare, ThresholdRSAVerifier } from "../src";
import { BigInteger, parseBigInteger } from "../src/utils";
import {
  generateThrowawayKey,
  loadThrowawayKey,
  makeSigners,
  makeVerifier,
  partialFor,
  shareConfig,
  verifierConfig,
} from "./fixtures";

const fx = loadThrowawayKey(1024);
const n = parseBigInteger(fx.publicKey.n);
const signers = makeSigners(fx);
const verifier = makeVerifier(fx);
const msg = () => crypto.randomBytes(32);

describe("combine: per-share value guards (SIG-13)", () => {
  it("node-forge is at or above the 1.4.0 modInverse(0) fix", () => {
    const v: string = require("node-forge/package.json").version;
    const [maj, min] = v.split(".").map(Number);
    expect(maj > 1 || (maj === 1 && min >= 4)).toBe(true);
  });

  it.each([
    ["zero", () => BigInteger.ZERO],
    ["a multiple of n (n)", () => n],
    ["a multiple of n (2n)", () => n.shiftLeft(1)],
    ["greater than n", () => n.add(new BigInteger("5"))],
    ["negative", () => new BigInteger("-7")],
  ])(
    "rejects a %s partial in the negative-Lagrange slot (index 2) and names it",
    (_label, bad) => {
      const m = msg();
      const started = Date.now();
      let caught: any;
      try {
        verifier.verifySignatureMessage(m, [
          partialFor(signers[0], 0, m),
          { signatureShare: bad(), shareIndex: 2 },
        ]);
      } catch (e) {
        caught = e;
      }
      expect(Date.now() - started).toBeLessThan(10_000); // must not hang
      expect(caught).toBeInstanceOf(CombineError);
      expect(caught.code).toBe("INVALID_SHARE");
      expect(caught.message).toMatch(/index 2/);
      expect(caught.rejectedShares).toEqual([
        expect.objectContaining({ shareIndex: 2, position: 1 }),
      ]);
    }
  );

  it("rejects a partial that shares a factor with n (gcd != 1) and names it", async () => {
    const { key, fixture } = await generateThrowawayKey(1024, 2, 3);
    const s = fixture.sharedKey.shares.map(
      (_, i) => new ThresholdRSAShare(shareConfig(fixture, i))
    );
    const v = new ThresholdRSAVerifier(verifierConfig(fixture));
    const m = msg();
    let caught: any;
    try {
      v.verifySignatureMessage(m, [
        { signatureShare: key.privateKey.p, shareIndex: 1 },
        partialFor(s[1], 1, m),
      ]);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CombineError);
    expect(caught.code).toBe("INVALID_SHARE");
    expect(caught.message).toMatch(/index 1/);
    expect(caught.message).toMatch(/coprime/i);
  });

  it("a rejected partial is skipped when enough valid partials remain", () => {
    const m = msg();
    const honest = verifier.verifySignatureMessage(m, [
      partialFor(signers[1], 1, m),
      partialFor(signers[2], 2, m),
    ]);
    const r = verifier.combineSignatureMessage(m, [
      { signatureShare: BigInteger.ZERO, shareIndex: 1 },
      partialFor(signers[1], 1, m),
      partialFor(signers[2], 2, m),
    ]);
    expect(r.signature).toBe(honest);
    expect(r.usedShareIndices).toEqual([2, 3]);
    expect(r.rejectedShares).toEqual([
      expect.objectContaining({ shareIndex: 1 }),
    ]);
  });

  it("rejects a malformed (non-hex) partial and routes around it when enough remain", () => {
    const m = msg();
    let caught: any;
    try {
      verifier.verifySignatureMessage(m, [
        { signatureShare: "not-hex!" as any, shareIndex: 1 },
        partialFor(signers[1], 1, m),
      ]);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CombineError);
    expect(caught.code).toBe("INVALID_SHARE");
    expect(caught.message).toMatch(/hex/i);
    const r = verifier.combineSignatureMessage(m, [
      { signatureShare: undefined as any, shareIndex: 1 },
      partialFor(signers[1], 1, m),
      partialFor(signers[2], 2, m),
    ]);
    expect(r.usedShareIndices).toEqual([2, 3]);
    expect(r.rejectedShares).toEqual([
      expect.objectContaining({
        shareIndex: 1,
        reason: expect.stringMatching(/malformed/),
      }),
    ]);
  });

  it("rejects an out-of-range share index and routes around it when enough remain", () => {
    const m = msg();
    for (const badIdx of [0, 7, 1.5]) {
      const r = verifier.combineSignatureMessage(m, [
        { ...partialFor(signers[0], 0, m), shareIndex: badIdx },
        partialFor(signers[1], 1, m),
        partialFor(signers[2], 2, m),
      ]);
      expect(r.usedShareIndices).toEqual([2, 3]);
      expect(r.rejectedShares[0].reason).toMatch(
        new RegExp(`Invalid share index ${badIdx}`)
      );
    }
    expect(() =>
      verifier.verifySignatureMessage(m, [
        { ...partialFor(signers[0], 0, m), shareIndex: 0 },
        partialFor(signers[1], 1, m),
      ])
    ).toThrow("Invalid share index 0");
  });

  it("accepts threshold/numParties/bits as decimal strings (env-sourced oracle config) and rejects other strings", () => {
    const m = msg();
    const stringy = new ThresholdRSAVerifier({
      ...verifierConfig(fx),
      threshold: "2" as any,
      numParties: "3" as any,
      bits: "1024" as any,
      verificationKeys: undefined,
    });
    const sig = stringy.verifySignatureMessage(m, [
      partialFor(signers[0], 0, m),
      partialFor(signers[1], 1, m),
    ]);
    expect(sig).toBe(
      verifier.verifySignatureMessage(m, [
        partialFor(signers[0], 0, m),
        partialFor(signers[1], 1, m),
      ])
    );
    expect(
      () =>
        new ThresholdRSAVerifier({
          ...verifierConfig(fx),
          numParties: "three" as any,
        })
    ).toThrow(TypeError);
    expect(
      () =>
        new ThresholdRSAShare({ ...shareConfig(fx, 0), bits: "1024" as any })
    ).not.toThrow();
  });

  it("accepts a partial given as a (strict) hex string", () => {
    const m = msg();
    const p = partialFor(signers[0], 0, m);
    const sig = verifier.verifySignatureMessage(m, [
      { signatureShare: p.signatureShare.toString(16), shareIndex: 1 },
      partialFor(signers[1], 1, m),
    ]);
    expect(sig.length).toBe(fx.bits / 4);
  });
});

describe("combine: k-subset retry (SIG-4)", () => {
  it("a corrupt share in front of two good ones no longer stalls the combine", () => {
    const m = msg();
    const honest = verifier.verifySignatureMessage(m, [
      partialFor(signers[1], 1, m),
      partialFor(signers[2], 2, m),
    ]);
    const bad = {
      signatureShare: new BigInteger("deadbeef", 16),
      shareIndex: 1,
    };
    const r = verifier.combineSignatureMessage(m, [
      bad,
      partialFor(signers[1], 1, m),
      partialFor(signers[2], 2, m),
    ]);
    expect(r.signature).toBe(honest);
    expect(r.usedShareIndices).toEqual([2, 3]);
    expect(r.failedSubsets).toEqual([[1, 2]]); // cyclic-window order: [1,2] then [2,3]
    expect(r.suspectShareIndices).toEqual([1]);
    expect(r.attempts).toBe(2);
    // the legacy string-returning API takes the same path
    expect(
      verifier.verifySignatureMessage(m, [
        bad,
        partialFor(signers[1], 1, m),
        partialFor(signers[2], 2, m),
      ])
    ).toBe(honest);
  });

  it("a share from a different key is routed around when two good ones exist", async () => {
    const { fixture: other } = await generateThrowawayKey(1024, 2, 3);
    const alien = new ThresholdRSAShare(shareConfig(other, 0));
    const m = msg();
    const r = verifier.combineSignatureMessage(m, [
      partialFor(alien, 0, m),
      partialFor(signers[1], 1, m),
      partialFor(signers[2], 2, m),
    ]);
    expect(r.usedShareIndices).toEqual([2, 3]);
    expect(r.suspectShareIndices).toEqual([1]);
  });

  it("with only k shares and one bad, throws NO_VALID_SUBSET naming the subset tried", () => {
    const m = msg();
    const relabelled = partialFor(signers[0], 0, m);
    relabelled.shareIndex = 2; // member misconfigured its share index
    let caught: any;
    try {
      verifier.verifySignatureMessage(m, [
        relabelled,
        partialFor(signers[2], 2, m),
      ]);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CombineError);
    expect(caught.code).toBe("NO_VALID_SUBSET");
    expect(caught.message).toMatch(/\[2, ?3\]/);
    expect(caught.attemptedSubsets).toEqual([[2, 3]]);
  });

  it("when every subset fails, the error lists all attempted subsets", () => {
    const m = msg();
    const bad = (i: number) => ({
      signatureShare: new BigInteger(String(1000 + i)),
      shareIndex: i,
    });
    let caught: any;
    try {
      verifier.verifySignatureMessage(m, [
        bad(1),
        bad(2),
        partialFor(signers[2], 2, m),
      ]);
    } catch (e) {
      caught = e;
    }
    expect(caught.code).toBe("NO_VALID_SUBSET");
    expect(caught.attemptedSubsets).toEqual([
      [1, 2],
      [2, 3],
      [1, 3],
    ]);
  });

  it("honours maxCombineAttempts", () => {
    const capped = makeVerifier(fx, { maxCombineAttempts: 1 });
    const m = msg();
    let caught: any;
    try {
      capped.verifySignatureMessage(m, [
        { signatureShare: new BigInteger("deadbeef", 16), shareIndex: 1 },
        partialFor(signers[1], 1, m),
        partialFor(signers[2], 2, m),
      ]);
    } catch (e) {
      caught = e;
    }
    expect(caught.code).toBe("NO_VALID_SUBSET");
    expect(caught.message).toMatch(/attempt cap/);
    expect(caught.attemptedSubsets).toEqual([[1, 2]]);
  });

  it("still rejects duplicate indices anywhere in the provided set", () => {
    const m = msg();
    let caught: any;
    try {
      verifier.verifySignatureMessage(m, [
        partialFor(signers[0], 0, m),
        partialFor(signers[1], 1, m),
        partialFor(signers[0], 0, m),
      ]);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CombineError);
    expect(caught.code).toBe("DUPLICATE_INDEX");
    expect(caught.message).toBe("Duplicate share indices detected");
  });

  it("still requires at least threshold shares", () => {
    const m = msg();
    expect(() =>
      verifier.verifySignatureMessage(m, [partialFor(signers[0], 0, m)])
    ).toThrow("Not enough shares to reconstruct signature");
  });

  it("first valid subset wins: output is identical to the 1.3.0 first-k behaviour for honest input", () => {
    const m = msg();
    const parts = signers.map((s, i) => partialFor(s, i, m));
    const r = verifier.combineSignatureMessage(m, parts);
    expect(r.usedShareIndices).toEqual([1, 2]);
    expect(r.attempts).toBe(1);
    expect(r.failedSubsets).toEqual([]);
    expect(r.signature).toBe(
      verifier.verifySignatureMessage(m, parts.slice(0, 2))
    );
  });
});
