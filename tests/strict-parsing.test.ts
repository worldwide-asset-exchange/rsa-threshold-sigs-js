// SIG-5 / SIG-12: strict hex parsing, structural checks at construction and the
// boot-time share self-check (`verifyShareConsistency`).
import {
  ShareConsistencyError,
  ThresholdRSAKey,
  ThresholdRSAShare,
  ThresholdRSAVerifier,
  verifyShareConsistency,
} from "../src";
import { BigInteger, parseBigInteger, toCanonicalHex } from "../src/utils";
import { loadThrowawayKey, shareConfig, verifierConfig } from "./fixtures";

const fx = loadThrowawayKey(1024);

describe("parseBigInteger is strict", () => {
  it("accepts hex of either case and odd length (value semantics)", () => {
    expect(parseBigInteger("ABCDEF").toString(16)).toBe("abcdef");
    expect(parseBigInteger("abc").equals(parseBigInteger("0abc"))).toBe(true);
    expect(parseBigInteger("0").signum()).toBe(0);
    expect(parseBigInteger("10001").intValue()).toBe(65537);
  });

  it("passes BigInteger instances through unchanged", () => {
    const x = new BigInteger("123456789abcdef", 16);
    expect(parseBigInteger(x)).toBe(x);
  });

  it.each([
    ["", "empty"],
    ["zz", "non-hex letters"],
    ["10 001", "inner whitespace"],
    ["10001\n", "trailing newline"],
    [" 10001", "leading space"],
    ["0x10001", "0x prefix"],
    ["-1", "sign"],
    ["+1", "sign"],
    ["1e5", "looks like hex but is fine"], // sanity: this one is valid hex and must NOT throw
  ])("%s (%s)", (input, label) => {
    if (label === "looks like hex but is fine") {
      expect(parseBigInteger(input).toString(16)).toBe("1e5");
    } else {
      expect(() => parseBigInteger(input)).toThrow(/hex/i);
    }
  });

  it("rejects non-string, non-BigInteger values", () => {
    for (const bad of [65537, undefined, null, {}, [], 1n] as any[]) {
      expect(() => parseBigInteger(bad)).toThrow(TypeError);
    }
  });

  it("toCanonicalHex pads to bits/4 lower-case and refuses values that do not fit", () => {
    expect(toCanonicalHex(new BigInteger("ff", 16), 32)).toBe("000000ff");
    expect(toCanonicalHex(BigInteger.ZERO, 8)).toBe("00");
    expect(() => toCanonicalHex(new BigInteger("1ff", 16), 8)).toThrow();
  });
});

describe("ThresholdRSAShare construction checks", () => {
  it("accepts the fixture", () => {
    expect(() => new ThresholdRSAShare(shareConfig(fx, 0))).not.toThrow();
  });

  it("rejects non-hex configuration values at construction", () => {
    expect(
      () =>
        new ThresholdRSAShare({ ...shareConfig(fx, 0), sharedKey: "not hex" })
    ).toThrow(/hex/i);
    expect(
      () =>
        new ThresholdRSAShare({
          ...shareConfig(fx, 0),
          publicKey: { n: fx.publicKey.n, e: "65537\n" },
        })
    ).toThrow(/hex/i);
  });

  it("rejects bits that disagree with n.bitLength()", () => {
    expect(
      () => new ThresholdRSAShare({ ...shareConfig(fx, 0), bits: 2048 })
    ).toThrow(/bitLength|bits/);
    expect(
      () => new ThresholdRSAShare({ ...shareConfig(fx, 0), bits: 1020 })
    ).toThrow(/multiple of 8|bits/);
  });

  it("rejects out-of-range values (0 or >= n)", () => {
    expect(
      () => new ThresholdRSAShare({ ...shareConfig(fx, 0), sharedKey: "0" })
    ).toThrow(/sharedKey/);
    expect(
      () =>
        new ThresholdRSAShare({ ...shareConfig(fx, 0), vku: fx.publicKey.n })
    ).toThrow(/vku/);
  });
});

describe("ThresholdRSAVerifier construction checks", () => {
  it("rejects bits that disagree with n.bitLength()", () => {
    expect(
      () => new ThresholdRSAVerifier(verifierConfig(fx, { bits: 2048 }))
    ).toThrow(/bitLength|bits/);
  });

  it("rejects a verificationKeys list of the wrong length or with non-hex entries", () => {
    expect(
      () =>
        new ThresholdRSAVerifier(
          verifierConfig(fx, {
            verificationKeys: fx.sharedKey.verificationKeys.slice(1),
          })
        )
    ).toThrow(/verificationKeys/);
    expect(
      () =>
        new ThresholdRSAVerifier(
          verifierConfig(fx, {
            verificationKeys: [
              ...fx.sharedKey.verificationKeys.slice(0, 2),
              "zz",
            ],
          })
        )
    ).toThrow(/hex/i);
  });

  it("rejects verificationKeys entries that are 0, >= n or not coprime to n", () => {
    const keys = [...fx.sharedKey.verificationKeys];
    keys[1] = "0";
    expect(
      () =>
        new ThresholdRSAVerifier(verifierConfig(fx, { verificationKeys: keys }))
    ).toThrow(/verificationKeys\[1\]/);
    keys[1] = fx.publicKey.n;
    expect(
      () =>
        new ThresholdRSAVerifier(verifierConfig(fx, { verificationKeys: keys }))
    ).toThrow(/verificationKeys\[1\]/);
  });

  it("still validates threshold/numParties", () => {
    expect(
      () => new ThresholdRSAVerifier(verifierConfig(fx, { threshold: 4 }))
    ).toThrow(/threshold/i);
  });
});

describe("verifyShareConsistency (boot-time self-check)", () => {
  it("returns a structured ok result for a correct share", () => {
    const r = verifyShareConsistency(shareConfig(fx, 1), {
      shareIndex: 2,
      numParties: 3,
      threshold: 2,
      verificationKeys: fx.sharedKey.verificationKeys,
      expectedPublicKey: { n: fx.publicKey.n.toUpperCase(), e: fx.publicKey.e },
    });
    expect(r.ok).toBe(true);
    expect(r.failures).toEqual([]);
    expect(r.bits).toBe(1024);
    expect(r.modulusHex).toBe(fx.publicKey.n.toLowerCase().padStart(256, "0"));
    expect(r.modulusHex.length).toBe(fx.bits / 4);
    expect(r.exponentHex).toBe("10001");
    expect(r.shareIndex).toBe(2);
    expect(r.checks.verificationKeyShare).toBe(true);
    expect(r.checks.vkuJacobi).toBe(true);
    expect(r.checks.modulusBits).toBe(true);
  });

  it("the share instance exposes the same check", () => {
    const share = new ThresholdRSAShare(shareConfig(fx, 0));
    expect(share.verifyConsistency().ok).toBe(true);
  });

  it("throws a descriptive error when the share and verification-key share do not match", () => {
    const cfg = {
      ...shareConfig(fx, 1),
      verificationKeyShare: fx.sharedKey.verificationKeys[0],
    };
    let caught: any;
    try {
      verifyShareConsistency(cfg);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ShareConsistencyError);
    expect(caught.message).toMatch(/verificationKeyShare/);
    expect(caught.result.ok).toBe(false);
    expect(caught.result.checks.verificationKeyShare).toBe(false);
    // non-throwing mode
    const r = verifyShareConsistency(cfg, { throwOnFailure: false });
    expect(r.ok).toBe(false);
    expect(r.failures.join(" ")).toMatch(/verificationKeyShare/);
  });

  it("detects a wrong share index against the dealer-published verification keys", () => {
    expect(() =>
      verifyShareConsistency(shareConfig(fx, 1), {
        shareIndex: 1,
        numParties: 3,
        verificationKeys: fx.sharedKey.verificationKeys,
      })
    ).toThrow(/shareIndex/);
  });

  it("detects a verificationKeys list whose length differs from numParties", () => {
    const r = verifyShareConsistency(shareConfig(fx, 1), {
      throwOnFailure: false,
      shareIndex: 2,
      numParties: 3,
      verificationKeys: fx.sharedKey.verificationKeys.slice(0, 2),
    });
    expect(r.ok).toBe(false);
    expect(r.checks.verificationKeysLength).toBe(false);
    expect(r.checks.shareIndex).toBe(true);
  });

  it("detects a vku with Jacobi symbol +1", () => {
    // v is a quadratic residue, so J(v|n) = +1: an invalid u parameter.
    expect(() =>
      verifyShareConsistency({ ...shareConfig(fx, 0), vku: fx.sharedKey.v })
    ).toThrow(/vku/);
  });

  it("detects a non-prime or too-small public exponent", () => {
    expect(() =>
      verifyShareConsistency({
        ...shareConfig(fx, 0),
        publicKey: { n: fx.publicKey.n, e: "10000" },
      })
    ).toThrow(/exponent/);
    expect(() =>
      verifyShareConsistency(
        { ...shareConfig(fx, 0), publicKey: { n: fx.publicKey.n, e: "3" } },
        { numParties: 3 }
      )
    ).toThrow(/exponent/);
  });

  it("detects a decimal exponent pasted as hex ('65537' is 0x65537)", () => {
    const r = verifyShareConsistency(
      { ...shareConfig(fx, 0), publicKey: { n: fx.publicKey.n, e: "65537" } },
      {
        throwOnFailure: false,
        expectedPublicKey: { n: fx.publicKey.n, e: "10001" },
      }
    );
    expect(r.ok).toBe(false);
    expect(r.failures.join(" ")).toMatch(/expectedPublicKey\.e/);
  });

  it("compares against an expected (e.g. on-chain) public key, including modulus width", () => {
    const r = verifyShareConsistency(shareConfig(fx, 0), {
      throwOnFailure: false,
      expectedPublicKey: { n: "0" + fx.publicKey.n, e: fx.publicKey.e },
    });
    expect(r.ok).toBe(false);
    expect(r.failures.join(" ")).toMatch(
      /expectedPublicKey\.n.*width|width.*expectedPublicKey\.n/
    );
  });

  it("rejects bits that disagree with the modulus", () => {
    expect(() =>
      verifyShareConsistency({ ...shareConfig(fx, 0), bits: 2048 })
    ).toThrow(/bits|bitLength/);
  });
});

describe("ThresholdRSAKey asserts n.bitLength() == bits (SIG-12)", () => {
  it.each([1024, 1032])("%i bits", async (bits) => {
    const key = new ThresholdRSAKey({ bits });
    await key.generateKeyPair();
    expect(key.publicKey.n.bitLength()).toBe(bits);
    expect(key.publicKey.n.toString(16).length).toBe(bits / 4);
  });
});
