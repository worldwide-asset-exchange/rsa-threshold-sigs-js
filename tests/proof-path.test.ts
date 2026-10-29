// SIG-1 / SIG-2 / SIG-11: proof-of-correctness path.
import crypto from "crypto";
import { ThresholdRSAShare } from "../src";
import { BigInteger, hashTranscript, parseBigInteger } from "../src/utils";
import {
  loadThrowawayKey,
  makeSigners,
  makeVerifier,
  partialWithProofFor,
  randomHashHex,
  shareConfig,
} from "./fixtures";

const fx = loadThrowawayKey(1024);
const n = parseBigInteger(fx.publicKey.n);
const v = parseBigInteger(fx.sharedKey.v);
const signers = makeSigners(fx);
const verifier = makeVerifier(fx);

describe("verifySharesHash uses dealer-published verification keys (SIG-1)", () => {
  it("accepts honest proofs from every party, looked up by shareIndex", () => {
    const h = randomHashHex();
    for (let i = 0; i < 3; i++) {
      expect(
        verifier.verifySharesHash(h, [partialWithProofFor(signers[i], i, h)])
      ).toBe(true);
    }
    expect(
      verifier.verifySharesHash(
        h,
        signers.map((s, i) => partialWithProofFor(s, i, h))
      )
    ).toBe(true);
  });

  it("rejects a forged share whose prover-supplied v_i is self-consistent but not the dealer's", () => {
    const h = randomHashHex((x) => /^[89a-f]/.test(x));
    const sPrime = new BigInteger(crypto.randomBytes(64).toString("hex"), 16);
    const vPrime = v.modPow(sPrime, n);
    const forger = new ThresholdRSAShare({
      ...shareConfig(fx, 1),
      sharedKey: sPrime,
      verificationKeyShare: vPrime,
    });
    const r = forger.signHash(h, { pkcs1: true, proof: true });
    const forged = {
      signatureShare: r.signatureShare,
      proof: r.proof,
      sharedVerificationKey: vPrime, // attacker-supplied, must be ignored
      shareIndex: 2,
    };
    expect(
      vPrime.equals(parseBigInteger(fx.sharedKey.verificationKeys[1]))
    ).toBe(false);
    expect(verifier.verifySharesHash(h, [forged])).toBe(false);
    const d = verifier.verifySharesHashDetailed(h, [forged]);
    expect(d.ok).toBe(false);
    expect(d.failures).toEqual([
      expect.objectContaining({ shareIndex: 2, position: 0 }),
    ]);
  });

  it("rejects an honest proof relabelled with another party's index", () => {
    const h = randomHashHex();
    const p = partialWithProofFor(signers[0], 0, h);
    p.shareIndex = 2;
    expect(verifier.verifySharesHash(h, [p])).toBe(false);
  });

  it.each(["z", "c", "signatureShare"])("rejects a tampered %s", (field) => {
    const h = randomHashHex();
    const p: any = partialWithProofFor(signers[0], 0, h);
    if (field === "signatureShare")
      p.signatureShare = p.signatureShare.add(BigInteger.ONE);
    else p.proof[field] = p.proof[field].add(BigInteger.ONE);
    expect(verifier.verifySharesHash(h, [p])).toBe(false);
  });

  it("returns false (not a TypeError) for a share without a proof or with a bad index", () => {
    const h = randomHashHex();
    const noProof = {
      signatureShare: signers[0].signHash(h).signatureShare,
      shareIndex: 1,
    };
    expect(verifier.verifySharesHash(h, [noProof])).toBe(false);
    const p = partialWithProofFor(signers[0], 0, h);
    expect(verifier.verifySharesHash(h, [{ ...p, shareIndex: 0 }])).toBe(false);
    expect(verifier.verifySharesHash(h, [{ ...p, shareIndex: 4 }])).toBe(false);
    expect(
      verifier.verifySharesHash(h, [{ ...p, signatureShare: BigInteger.ZERO }])
    ).toBe(false);
  });

  it("returns false for proofs whose z/c are strings, null or out of range (no TypeError)", () => {
    const h = randomHashHex();
    const p: any = partialWithProofFor(signers[0], 0, h);
    expect(
      verifier.verifySharesHash(h, [
        {
          ...p,
          proof: { z: p.proof.z.toString(16), c: p.proof.c.toString(16) },
        },
      ])
    ).toBe(true); // hex strings are fine
    expect(
      verifier.verifySharesHash(h, [{ ...p, proof: { z: "zz", c: p.proof.c } }])
    ).toBe(false);
    expect(
      verifier.verifySharesHash(h, [{ ...p, proof: { z: null, c: p.proof.c } }])
    ).toBe(false);
    expect(
      verifier.verifySharesHash(h, [
        { ...p, proof: { z: p.proof.z.negate(), c: p.proof.c } },
      ])
    ).toBe(false);
    expect(
      verifier.verifySharesHash(h, [
        { ...p, proof: { z: p.proof.z, c: BigInteger.ONE.shiftLeft(300) } },
      ])
    ).toBe(false);
    const d = verifier.verifySharesHashDetailed(h, [
      { ...p, proof: { z: "zz", c: p.proof.c } },
    ]);
    expect(d.failures[0].reason).toMatch(/hex/i);
  });

  it("throws if the verifier was built without verificationKeys", () => {
    const bare = makeVerifier(fx, { verificationKeys: undefined });
    const h = randomHashHex();
    expect(() =>
      bare.verifySharesHash(h, [partialWithProofFor(signers[0], 0, h)])
    ).toThrow(/verificationKeys/);
    // the combine path does not need them
    expect(() =>
      bare.verifySignatureHash(h, [
        partialWithProofFor(signers[0], 0, h),
        partialWithProofFor(signers[1], 1, h),
      ])
    ).not.toThrow();
  });

  it("still rejects an empty share set", () => {
    expect(verifier.verifySharesHash(randomHashHex(), [])).toBe(false);
  });

  it("verifies a pkcs1=false proof and a message-based proof", () => {
    const h = randomHashHex();
    const raw = signers[2].signHash(h, { pkcs1: false, proof: true });
    expect(
      verifier.verifySharesHash(
        h,
        [
          {
            signatureShare: raw.signatureShare,
            proof: raw.proof,
            shareIndex: 3,
          },
        ],
        false
      )
    ).toBe(true);
    const message = "proof over a message";
    const hm = crypto.createHash("sha256").update(message).digest("hex");
    const r = signers[0].signMessage(message, { pkcs1: true, proof: true });
    expect(
      verifier.verifySharesMessage(message, [
        { signatureShare: r.signatureShare, proof: r.proof, shareIndex: 1 },
      ])
    ).toBe(true);
    expect(
      verifier.verifySharesHash(hm, [
        { signatureShare: r.signatureShare, proof: r.proof, shareIndex: 1 },
      ])
    ).toBe(true);
  });
});

describe("digest padding is shared by sign, combine and proof (SIG-2)", () => {
  it("honest proofs verify for hashes with a leading zero nibble and a leading zero byte", () => {
    for (let k = 0; k < 8; k++) {
      const h = randomHashHex((x) => x[0] === "0");
      for (let i = 0; i < 3; i++) {
        expect(
          verifier.verifySharesHash(h, [partialWithProofFor(signers[i], i, h)])
        ).toBe(true);
      }
    }
    const h00 = randomHashHex((x) => x.startsWith("00"));
    expect(
      verifier.verifySharesHash(h00, [partialWithProofFor(signers[0], 0, h00)])
    ).toBe(true);
    // a hash handed over as a BigInteger (no leading zeros in its hex form) is padded identically
    const hBig = new BigInteger(h00, 16);
    expect(
      verifier.verifySharesHash(hBig, [partialWithProofFor(signers[1], 1, h00)])
    ).toBe(true);
    const r = signers[2].signHash(hBig, { proof: true });
    expect(
      verifier.verifySharesHash(h00, [
        { signatureShare: r.signatureShare, proof: r.proof, shareIndex: 3 },
      ])
    ).toBe(true);
  });

  it("the combine on a leading-zero-nibble hash still succeeds", () => {
    const h = randomHashHex((x) => x[0] === "0");
    const sig = verifier.verifySignatureHash(h, [
      partialWithProofFor(signers[0], 0, h),
      partialWithProofFor(signers[2], 2, h),
    ]);
    expect(sig.length).toBe(fx.bits / 4);
  });

  it("rejects hashes longer than 256 bits or not hex", () => {
    expect(() => signers[0].signHash("0" + randomHashHex() + "1")).toThrow(
      /256 bits/
    );
    expect(() => signers[0].signHash("nothex")).toThrow(/hex/i);
    const h = randomHashHex();
    const two = [
      partialWithProofFor(signers[0], 0, h),
      partialWithProofFor(signers[1], 1, h),
    ];
    expect(() => verifier.verifySignatureHash("zz", two)).toThrow(/hex/i);
    expect(() => verifier.verifySharesHash("zz", two)).toThrow(/hex/i);
  });
});

describe("hashTranscript has length framing and a domain tag (SIG-11)", () => {
  const T = (vals: string[]) => {
    const [v, xt, vi, xi2, vp, xp] = vals.map((x) => new BigInteger(x, 16));
    return { v, xt, vi, xi2, vp, xp };
  };

  it("distinguishes transcripts whose unframed byte concatenation is identical", () => {
    const a = hashTranscript(T(["01", "0203", "04", "05", "06", "07"]));
    const b = hashTranscript(T(["0102", "03", "04", "05", "06", "07"]));
    expect(a.equals(b)).toBe(false);
  });

  it("is deterministic and 256 bits wide", () => {
    const a = hashTranscript(T(["0a", "14", "1e", "28", "32", "3c"]));
    const b = hashTranscript(T(["0a", "14", "1e", "28", "32", "3c"]));
    expect(a.equals(b)).toBe(true);
    expect(a.bitLength()).toBeLessThanOrEqual(256);
  });
});
