// SIG-8: the secret-share exponentiation is blinded; outputs must be bit-identical
// to the unblinded computation.
import crypto from "crypto";
import {
  BigInteger,
  blindedModPow,
  modPowLadder,
  modPowNative,
  parseBigInteger,
} from "../src/utils";
import { loadThrowawayKey, makeSigners, randomHashHex } from "./fixtures";

const fx = loadThrowawayKey(1024);
const n = parseBigInteger(fx.publicKey.n);
const toBig = (x: typeof BigInteger) => BigInt("0x" + x.toString(16));

describe("modPowLadder", () => {
  it("equals square-and-multiply for random operands and edge cases", () => {
    const nBig = toBig(n);
    for (let i = 0; i < 50; i++) {
      const base = BigInt("0x" + crypto.randomBytes(128).toString("hex"));
      const exp = BigInt(
        "0x" + crypto.randomBytes(16 + (i % 100)).toString("hex")
      );
      expect(modPowLadder(base, exp, nBig)).toBe(modPowNative(base, exp, nBig));
    }
    expect(modPowLadder(5n, 0n, nBig)).toBe(1n);
    expect(modPowLadder(5n, 1n, nBig)).toBe(5n);
    expect(modPowLadder(0n, 7n, nBig)).toBe(0n);
    expect(modPowLadder(7n, 3n, 1n)).toBe(0n);
    expect(modPowLadder(88n, 2n, 65n)).toBe(9n);
  });
});

describe("blindedModPow", () => {
  it("equals the plain modular exponentiation for random bases and secret exponents", () => {
    for (let i = 0; i < 50; i++) {
      const base = new BigInteger(
        crypto.randomBytes(128).toString("hex"),
        16
      ).mod(n);
      const exp = new BigInteger(crypto.randomBytes(128).toString("hex"), 16);
      const expected = modPowNative(toBig(base), toBig(exp), toBig(n));
      expect(blindedModPow(base, exp, n).toString(16)).toBe(
        expected.toString(16)
      );
    }
  });

  it("handles the degenerate bases 0 and 1 and a base that is a multiple of n", () => {
    const exp = new BigInteger(crypto.randomBytes(64).toString("hex"), 16);
    expect(blindedModPow(BigInteger.ZERO, exp, n).signum()).toBe(0);
    expect(blindedModPow(BigInteger.ONE, exp, n).equals(BigInteger.ONE)).toBe(
      true
    );
    expect(blindedModPow(n.shiftLeft(1), exp, n).signum()).toBe(0);
  });

  it("is deterministic across calls (blinding randomness never leaks into the output)", () => {
    const base = new BigInteger(crypto.randomBytes(100).toString("hex"), 16);
    const exp = new BigInteger(crypto.randomBytes(100).toString("hex"), 16);
    const a = blindedModPow(base, exp, n);
    const b = blindedModPow(base, exp, n);
    expect(a.equals(b)).toBe(true);
  });
});

describe("signHash output equals the unblinded x~^(2 s_i) mod n", () => {
  const signers = makeSigners(fx);
  it.each([0, 1, 2])("party %i", (i) => {
    const s = parseBigInteger(fx.sharedKey.shares[i]);
    for (let k = 0; k < 10; k++) {
      const h = randomHashHex();
      const r = signers[i].signHash(h);
      const reference = r.msgBigIntToSign.modPow(s.shiftLeft(1), n); // jsbn, unblinded
      expect(r.signatureShare.equals(reference)).toBe(true);
    }
  });
});
