import forge from "node-forge";
import crypto from 'crypto';

export const BigInteger = forge.jsbn.BigInteger;

Object.defineProperty(BigInteger, 'TWO', {
    get: function() {
        return new BigInteger('2');
    }
});

const HEX_RE = /^[0-9a-fA-F]+$/;

// Duck-typed check for a jsbn BigInteger. `instanceof` is deliberately avoided:
// a consumer may hand us a BigInteger built from its own copy of node-forge.
export function isBigInteger(value: any): boolean {
	return value !== null && typeof value === 'object'
		&& typeof value.compareTo === 'function'
		&& typeof value.modPow === 'function'
		&& typeof value.toString === 'function'
		&& typeof value.bitLength === 'function';
}

// Normalise a hex string the way an env/secret value may arrive: surrounding
// whitespace (incl. a trailing newline) is trimmed and one optional 0x/0X prefix
// is removed. Nothing else is touched — interior characters must all be hex.
function normalizeHexString(value: string): string {
	const trimmed = value.trim();
	return /^0[xX]/.test(trimmed) ? trimmed.slice(2) : trimmed;
}

// Strict hex → BigInteger. Accepts [0-9a-fA-F]+ (either case, any length; odd
// length is fine because the string is read as an integer, so "abc" == "0abc"
// and leading zeros carry no meaning), optionally surrounded by whitespace and
// optionally prefixed with 0x/0X (both tolerated so 1.3.0-era secrets with a
// trailing newline or a prefix stay drop-in). Rejects empty strings (also after
// trimming/prefix removal), signs and any interior non-hex character — jsbn's
// own parser silently skipped every non-hex character (SIG-5), which turned
// "1 001" or a decimal exponent into a different, well-formed number.
// BigInteger instances pass through unchanged.
// NOTE: a decimal string made of hex digits ("65537") is still read AS HEX; the
// library has always treated strings as hex and this is not a change.
export const parseBigInteger = (value: typeof BigInteger | string, label: string = 'value'): typeof BigInteger => {
	if (typeof value === 'string') {
		const hex = normalizeHexString(value);
		if (!HEX_RE.test(hex)) {
			throw new Error(`${label} must be a non-empty hex string ([0-9a-fA-F]+, optional 0x prefix and surrounding whitespace); got ${JSON.stringify(value.length > 40 ? value.slice(0, 40) + '…' : value)}`);
		}
		return new BigInteger(hex, 16);
	}
	if (isBigInteger(value)) {
		return value;
	}
	throw new TypeError(`${label} must be a hex string or a BigInteger; got ${value === null ? 'null' : typeof value}`);
}

// Lower-case hex, zero-padded to exactly bits/4 characters. Throws if the value
// does not fit (it never should for a value < n when n.bitLength() == bits).
export function toCanonicalHex(value: typeof BigInteger, bits: number): string {
	if (value.signum() < 0) throw new Error('toCanonicalHex: negative value');
	const hex = value.toString(16);
	const width = bits / 4;
	if (hex.length > width) throw new Error(`toCanonicalHex: value has ${hex.length} hex digits, wider than bits/4 = ${width}`);
	return hex.padStart(width, '0');
}

// Integer parameters (bits, threshold, numParties, …) arrive from the consumer's
// config layer, where env-sourced values are strings. 1.3.0 coerced them
// implicitly; accept a non-negative integer or a decimal digit string, reject
// anything else explicitly.
export function coerceInteger(value: any, label: string): number {
	if (typeof value === 'number' && Number.isInteger(value)) return value;
	if (typeof value === 'string' && /^\d+$/.test(value.trim())) return Number(value.trim());
	throw new TypeError(`${label} must be an integer (number or decimal string); got ${JSON.stringify(value)}`);
}

// Primality via OpenSSL (node:crypto) — the single primality path for public
// exponents (ThresholdRSAKey.validateParams, verifyShareConsistency).
export function isPrimeNative(value: typeof BigInteger | number | bigint): boolean {
	const big = typeof value === 'bigint' ? value : typeof value === 'number' ? BigInt(value) : BigInt('0x' + value.toString(16));
	if (big < 2n) return false;
	return crypto.checkPrimeSync(big);
}

// Structural check shared by every place a modulus and a bit size meet (SIG-12):
// the on-chain verifier requires len(sig_hex) == len(modulus_hex) and the library
// pads signatures to bits/4, so both only line up when n.bitLength() == bits with
// bits a multiple of 8 (which makes the hex width exactly bits/4).
export function assertModulusBits(n: typeof BigInteger, bits: number, label: string = 'publicKey.n') {
	if (!Number.isInteger(bits) || bits <= 0 || bits % 8 !== 0) {
		throw new Error(`bits must be a positive multiple of 8; got ${bits}`);
	}
	if (n.bitLength() !== bits) {
		throw new Error(`${label}.bitLength() is ${n.bitLength()} but bits is ${bits}`);
	}
	if (!n.testBit(0)) {
		throw new Error(`${label} must be odd`);
	}
}

export function modPowNative(base, exponent, modulus) {
	if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    exponent >>= 1n;
    base = (base * base) % modulus;
  }
  return result;
}
// Generate a uniformly random BigInt in [0, n) via rejection sampling.
// Allocates ceil(bitLength/8) bytes and masks the excess high bits so each
// candidate spans the full bit length of n before the rejection check. Using
// floor(bitLength/8) (as a previous version did) silently truncated values
// whenever n.bitLength() was not a multiple of 8, biasing the output to a
// strictly smaller range and never exercising the rejection loop.
function uniformRandomBelow(n: typeof BigInteger): typeof BigInteger {
	const bits = n.bitLength();
	const numBytes = Math.ceil(bits / 8);
	const excessBits = numBytes * 8 - bits;
	let result: typeof BigInteger;
	do {
		const bytes = crypto.randomBytes(numBytes);
		// Clear the high bits that overflow n's bit length so the candidate is
		// uniform over [0, 2^bits) rather than [0, 2^(numBytes*8)).
		bytes[0] &= 0xff >> excessBits;
		result = new BigInteger(bytes.toString('hex'), 16);
	} while (result.compareTo(n) >= 0);
	return result;
}

// Generate a random BigInt less than n
export function randomBigInt(n: typeof BigInteger): typeof BigInteger {
	return uniformRandomBelow(n);
}

// Generate a random BigInt in [0, n) that is coprime with n
export function randomBigIntCoprime(n: typeof BigInteger): typeof BigInteger {
	let random: typeof BigInteger;
	do {
		random = uniformRandomBelow(n);
	} while (random.gcd(n).compareTo(BigInteger.ONE) !== 0);
	return random;
}

// Hash a transcript (object) to create a challenge.
// Framing (SIG-11): a fixed domain tag, then each element as a 4-byte big-endian
// length prefix followed by its two's-complement big-endian bytes, so no two
// distinct element sequences share a preimage. Changed in 2.0.0 — proofs made
// by earlier versions do not verify (proofs are not persisted anywhere).
const TRANSCRIPT_TAG = Buffer.from('waxio/rsa-threshold-signatures/shoup-proof/v2', 'utf8');
export function hashTranscript(transcript: any) {
	const h = crypto.createHash('sha256');
	h.update(TRANSCRIPT_TAG);
	for (const field of ['v', 'xt', 'vi', 'xi2', 'vp', 'xp']) {
		const bytes = Buffer.from(transcript[field].toByteArray());
		const len = Buffer.alloc(4);
		len.writeUInt32BE(bytes.length, 0);
		h.update(len);
		h.update(bytes);
	}
	return new BigInteger(h.digest('hex'), 16);
}

// Montgomery-ladder modular exponentiation: one multiply and one square per
// exponent bit in a fixed order, whatever the bit is. Used for SECRET exponents
// (modPowNative's square-and-multiply skips the multiply on 0 bits). V8 BigInt
// arithmetic itself is not constant-time, so this removes the operation-pattern
// leak, not every timing signal — see CHANGELOG (SIG-8 residual).
export function modPowLadder(base: bigint, exponent: bigint, modulus: bigint): bigint {
	if (modulus === 1n) return 0n;
	let r0 = 1n;
	let r1 = base % modulus;
	for (let i = exponent.toString(2).length - 1; i >= 0; i--) {
		if ((exponent >> BigInt(i)) & 1n) {
			r0 = (r0 * r1) % modulus;
			r1 = (r1 * r1) % modulus;
		} else {
			r1 = (r0 * r1) % modulus;
			r0 = (r0 * r0) % modulus;
		}
	}
	return r0;
}

// Blinded modular exponentiation with a SECRET exponent (SIG-8).
//   r ← random in Z_n^*;  y = (base·r)^exp · (r^exp)^{-1} mod n = base^exp mod n
// The exponentiation that touches `exp` therefore never runs on an input the
// caller (or a requester upstream of the caller) chose, and both exponentiations
// use the fixed-pattern ladder. Classic RSA blinding unblinds with r^{-1} because
// the exponent is d and (r^e)^d = r; a Shoup share exponent 2·s_i has no public
// inverse exponent, so r^exp is computed explicitly — one extra exponentiation
// on a random base. Output is bit-identical to the unblinded computation (tested).
export function blindedModPow(base: typeof BigInteger, exp: typeof BigInteger, n: typeof BigInteger): typeof BigInteger {
	const nBig = BigInt('0x' + n.toString(16));
	const expBig = BigInt('0x' + exp.toString(16));
	const baseModN = base.mod(n);
	if (baseModN.signum() === 0) return BigInteger.ZERO;
	const r = randomBigIntCoprime(n);
	const rBig = BigInt('0x' + r.toString(16));
	const blinded = (BigInt('0x' + baseModN.toString(16)) * rBig) % nBig;
	const yBlinded = modPowLadder(blinded, expBig, nBig);
	const rExp = modPowLadder(rBig, expBig, nBig);
	const rExpInv = new BigInteger(rExp.toString(16), 16).modInverse(n);
	const y = (yBlinded * BigInt('0x' + rExpInv.toString(16))) % nBig;
	return new BigInteger(y.toString(16), 16);
}

// The one digest→integer encoder used by sign, combine and proof (SIG-2):
// `hash` is a SHA-256 digest as hex (strict) or BigInteger, at most 256 bits;
// it is zero-padded to 32 bytes and, with pkcs1, wrapped in EMSA-PKCS1-v1_5
// for a bits/8-byte modulus. verifySharesHash previously skipped the padding and
// dropped a nibble for ~1/16 of digests.
export function digestToSigningInteger(hash: typeof BigInteger | string, bits: number, pkcs1: boolean): typeof BigInteger {
	const digest = parseBigInteger(hash, 'hash');
	if (digest.bitLength() > 256) {
		throw new Error('Message hash must be 256 bits or less');
	}
	if (!pkcs1) return digest;
	const digestBytes = Buffer.from(digest.toString(16).padStart(64, '0'), 'hex');
	return new BigInteger(emsaPkcs1v15encode(digestBytes, bits).toString('hex'), 16);
}

// Shoup §4: if J(x|n) = −1, sign x̃ = x·u^e instead; the combiner divides u back out.
export function applyJacobiLift(x: typeof BigInteger, n: typeof BigInteger, e: typeof BigInteger, vku: typeof BigInteger): { x: typeof BigInteger, lifted: boolean } {
	if (jacobiSymbol(x, n) === -1) {
		return { x: x.multiply(vku.modPow(e, n)).mod(n), lifted: true };
	}
	return { x, lifted: false };
}

// k-element index subsets of [0, count) in lexicographic order (first k first).
export function* kSubsets(count: number, k: number): Generator<number[]> {
	if (k > count || k <= 0) return;
	const idx = Array.from({ length: k }, (_, i) => i);
	while (true) {
		yield idx.slice();
		let i = k - 1;
		while (i >= 0 && idx[i] === count - k + i) i--;
		if (i < 0) return;
		idx[i]++;
		for (let j = i + 1; j < k; j++) idx[j] = idx[j - 1] + 1;
	}
}

// Order in which the combine tries k-subsets of `count` candidate positions:
// first the `count` cyclic windows of k consecutive positions (the first window
// is positions 0..k-1, i.e. 1.3.0's behaviour), so that any single bad share
// is excluded within `count` attempts for every (k, l); then every remaining
// subset in lexicographic order (bounded by the caller's attempt cap).
export function* combineSubsetOrder(count: number, k: number): Generator<number[]> {
	if (k > count || k <= 0) return;
	const seen = new Set<string>();
	for (let start = 0; start < count; start++) {
		const window = Array.from({ length: k }, (_, j) => (start + j) % count).sort((a, b) => a - b);
		const key = window.join(',');
		if (seen.has(key)) continue;
		seen.add(key);
		yield window;
	}
	for (const subset of kSubsets(count, k)) {
		const key = subset.join(',');
		if (seen.has(key)) continue;
		seen.add(key);
		yield subset;
	}
}

// Calculate Lagrange coefficient
export function lagrangeCoefficient(S: typeof BigInteger[], i: typeof BigInteger, j: typeof BigInteger, delta: typeof BigInteger) {
	let result = delta;

	for (const jPrime of S) {
		if (!jPrime.equals(j)) {
			// Use BigInt division instead of regular division
			const numerator = i.subtract(jPrime);
			const denominator = j.subtract(jPrime);
			result = result.multiply(numerator).divide(denominator);
		}
	}

	return result;
}

// Extended GCD - returns [gcd(a,b), x, y] where ax + by = gcd(a,b)
export function extendedGCD(a: typeof BigInteger, b: typeof BigInteger) {
	if (a.equals(BigInteger.ZERO)) {
		return [b, BigInteger.ZERO, BigInteger.ONE];
	} else {
		const [g, x, y] = extendedGCD(b.mod(a), a);
		return [g, y.subtract(b.divide(a).multiply(x)), x];
	}
}

export function generateSafePrime(bits: number) {
  const p = crypto.generatePrimeSync(bits, { safe: true });
	return new BigInteger(Buffer.from(p).toString('hex'), 16);
}

export function jacobiSymbol(a: typeof BigInteger, n: typeof BigInteger): number {
    // Check if n is positive and odd
    if (n.compareTo(BigInteger.ZERO) <= 0 || n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
        throw new Error('n must be positive and odd');
    }

    // Initialize result
    let result = 1;

    // Make a positive using proper modular arithmetic
    if (a.compareTo(BigInteger.ZERO) < 0) {
        a = a.mod(n).add(n).mod(n);
    }

		a = a.mod(n);

    // Main loop
    while (!a.equals(BigInteger.ZERO)) {
        // Rule 2: (2/n) = (-1)^((n^2-1)/8)
        while (a.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            a = a.divide(BigInteger.TWO);
            const nMod8 = n.mod(new BigInteger('8'));
            if (nMod8.equals(new BigInteger('3')) || nMod8.equals(new BigInteger('5'))) {
                result = -result;
            }
        }

				// Swap a and n
				[a, n] = [n, a];
        // Rule 3: Quadratic Reciprocity
        if (a.mod(new BigInteger('4')).equals(new BigInteger('3')) && 
            n.mod(new BigInteger('4')).equals(new BigInteger('3'))) {
            result = -result;
        }

        a = a.mod(n);
    }

    // If n == 1, return result, else return 0
    return n.equals(BigInteger.ONE) ? result : 0;
}

export function emsaPkcs1v15encode(hash: Buffer, bits: number) {
	const k = bits / 8;
	const derPrefix = Buffer.from('3031300d060960864801650304020105000420', 'hex');
	const T = Buffer.concat([derPrefix, hash]); // DigestInfo (51 bytes)

	const psLength = k - T.length - 3;
	if (psLength < 8) throw new Error("Intended encoded message too short");

	// Create PS (padding string) of 0xFFs
	const PS = Buffer.alloc(psLength, 0xff);

	// Final EMSA-PKCS1-v1_5 encoded block
	const EM = Buffer.concat([
		Buffer.from([0x00, 0x01]),
		PS,
		Buffer.from([0x00]),
		T
	]);
	return EM;
}

// Simple primality test using Miller-Rabin
export function isPrime(n: typeof BigInteger, k: number = 10): boolean {
	if (n.compareTo(BigInteger.ONE) <= 0) return false;
	if (n.equals(BigInteger.TWO)) return true;
	if (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) return false;

	// Write n-1 as d * 2^r
	let r = 0;
	let d = n.subtract(BigInteger.ONE);
	while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
		d = d.divide(BigInteger.TWO);
		r++;
	}

	// Perform k rounds of testing
	for (let i = 0; i < k; i++) {
		const a = randomBigInt(n.subtract(BigInteger.TWO)).add(BigInteger.TWO); // 2 <= a <= n-2
		let x = a.modPow(d, n);

		if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE))) {
			continue;
		}

		let composite = true;
		for (let j = 0; j < r - 1; j++) {
			x = x.modPow(BigInteger.TWO, n);
			if (x.equals(n.subtract(BigInteger.ONE))) {
				composite = false;
				break;
			}
		}

		if (composite) return false;
	}

	return true;
}

// Safe factorial calculation with practical limits
export function safeFactorial(n: typeof BigInteger, maxBits: number = 8192): typeof BigInteger {
	if (n.compareTo(new BigInteger('170')) > 0) {
		throw new Error(`Factorial too large: ${n.toString()}! would exceed ${maxBits} bits. Consider reducing number of parties.`);
	}
	
	let result = BigInteger.ONE;
	for (let i = BigInteger.TWO; i.compareTo(n) <= 0; i = i.add(BigInteger.ONE)) {
		result = result.multiply(i);
		// Check if result is getting too large
		if (result.bitLength() > maxBits) {
			throw new Error(`Factorial calculation exceeded ${maxBits} bits. Consider reducing number of parties.`);
		}
	}
	return result;
}