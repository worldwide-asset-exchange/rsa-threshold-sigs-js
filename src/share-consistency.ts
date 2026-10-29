import crypto from 'crypto';
import { BigInteger, parseBigInteger, jacobiSymbol, toCanonicalHex } from './utils';
import type { ThresholdRSAShareConfig } from './threshold-rsa-share';

export type ShareConsistencyOptions = {
	// 1-based index of this party; enables the verificationKeys[shareIndex-1] check.
	shareIndex?: number;
	numParties?: number;
	threshold?: number;
	// Dealer-published per-party verification keys v_i (length numParties).
	verificationKeys?: (typeof BigInteger | string)[];
	// An independently sourced public key (e.g. the on-chain `pubkeys` row) that the
	// local configuration must agree with, numerically and in modulus hex width.
	expectedPublicKey?: { n: string; e: string };
	// Default true: throw ShareConsistencyError on any failed check.
	throwOnFailure?: boolean;
};

export type ShareConsistencyChecks = {
	modulusBits: boolean;          // n.bitLength() == bits and hex width == bits/4
	modulusOdd: boolean;
	exponentPrime: boolean;        // e is an odd prime > 2 (Shoup requires a prime e)
	exponentAboveParties: boolean; // e > numParties (only when numParties given)
	thresholdRange: boolean;       // 1 <= threshold <= numParties (only when both given)
	shareIndexRange: boolean;      // 1 <= shareIndex <= numParties (only when given)
	sharedKeyRange: boolean;       // 0 < s_i and s_i.bitLength() <= bits - 2 (s_i < m < n/4)
	verificationKeyRange: boolean; // 0 < v < n, gcd(v, n) = 1, J(v|n) = +1 (v ∈ Q_n)
	verificationKeyShareRange: boolean; // 0 < v_i < n, gcd(v_i, n) = 1
	vkuRange: boolean;             // 0 < u < n, gcd(u, n) = 1
	vkuJacobi: boolean;            // J(u|n) = -1
	verificationKeyShare: boolean; // v^{s_i} mod n == v_i  (the actual share/key binding)
	shareIndex: boolean;           // verificationKeys[shareIndex-1] == v_i (only when both given)
	expectedPublicKey: boolean;    // matches expectedPublicKey (only when given)
};

export type ShareConsistencyResult = {
	ok: boolean;
	failures: string[];
	checks: ShareConsistencyChecks;
	bits: number;
	shareIndex?: number;
	// Canonical lower-case hex of the local public key, bits/4 wide — compare it
	// with whatever the verifier side (contract) holds.
	modulusHex: string;
	exponentHex: string;
};

export class ShareConsistencyError extends Error {
	public readonly result: ShareConsistencyResult;
	constructor(result: ShareConsistencyResult) {
		super(`Threshold RSA share configuration failed ${result.failures.length} consistency check(s): ${result.failures.join('; ')}`);
		this.name = 'ShareConsistencyError';
		this.result = result;
	}
}

function inRangeCoprime(x: typeof BigInteger, n: typeof BigInteger): boolean {
	return x.signum() > 0 && x.compareTo(n) < 0 && x.gcd(n).equals(BigInteger.ONE);
}

function isOddPrime(e: typeof BigInteger): boolean {
	if (e.compareTo(BigInteger.TWO) <= 0 || !e.testBit(0)) return false;
	return crypto.checkPrimeSync(BigInt('0x' + e.toString(16)));
}

// Boot-time self-check for one party's share configuration (SIG-5). Every check is
// cheap except `verificationKeyShare` (one modexp with the share exponent, ~tens of
// ms at 4096 bits), which is the one that actually binds the share to the public
// verification key and catches a share/index/key mix-up before the first partial.
// Returns the structured result; throws ShareConsistencyError on any failure
// unless `throwOnFailure: false`.
export function verifyShareConsistency(config: ThresholdRSAShareConfig, options: ShareConsistencyOptions = {}): ShareConsistencyResult {
	const failures: string[] = [];
	const fail = (check: keyof ShareConsistencyChecks, message: string) => {
		checks[check] = false;
		failures.push(message);
	};
	const checks: ShareConsistencyChecks = {
		modulusBits: true, modulusOdd: true, exponentPrime: true, exponentAboveParties: true,
		thresholdRange: true, shareIndexRange: true, sharedKeyRange: true, verificationKeyRange: true,
		verificationKeyShareRange: true, vkuRange: true, vkuJacobi: true, verificationKeyShare: true,
		shareIndex: true, expectedPublicKey: true,
	};

	// Parsing is strict and throws on malformed input: that is a configuration error,
	// not a consistency result.
	const bits = config.bits;
	const n = parseBigInteger(config.publicKey.n, 'publicKey.n');
	const e = parseBigInteger(config.publicKey.e, 'publicKey.e');
	const s = parseBigInteger(config.sharedKey, 'sharedKey');
	const v = parseBigInteger(config.verificationKey, 'verificationKey');
	const vi = parseBigInteger(config.verificationKeyShare, 'verificationKeyShare');
	const u = parseBigInteger(config.vku, 'vku');
	const verificationKeys = options.verificationKeys?.map((k, i) => parseBigInteger(k, `verificationKeys[${i}]`));

	if (!Number.isInteger(bits) || bits <= 0 || bits % 8 !== 0 || n.bitLength() !== bits || n.toString(16).length !== bits / 4) {
		fail('modulusBits', `publicKey.n.bitLength() is ${n.bitLength()} (hex width ${n.toString(16).length}) but bits is ${bits} (need bitLength == bits, width == bits/4, bits % 8 == 0)`);
	}
	if (!n.testBit(0)) fail('modulusOdd', 'publicKey.n is even');
	if (!isOddPrime(e)) fail('exponentPrime', `public exponent e = 0x${e.toString(16)} is not an odd prime`);
	if (options.numParties !== undefined && e.compareTo(new BigInteger(String(options.numParties))) <= 0) {
		fail('exponentAboveParties', `public exponent e = 0x${e.toString(16)} must exceed numParties = ${options.numParties}`);
	}
	if (options.numParties !== undefined && options.threshold !== undefined
		&& (!Number.isInteger(options.threshold) || options.threshold < 1 || options.threshold > options.numParties)) {
		fail('thresholdRange', `threshold ${options.threshold} is outside [1, numParties = ${options.numParties}]`);
	}
	if (options.shareIndex !== undefined
		&& (!Number.isInteger(options.shareIndex) || options.shareIndex < 1
			|| (options.numParties !== undefined && options.shareIndex > options.numParties)
			|| (verificationKeys && options.shareIndex > verificationKeys.length))) {
		fail('shareIndexRange', `shareIndex ${options.shareIndex} is outside [1, numParties]`);
	}
	if (s.signum() <= 0 || (checks.modulusBits && s.bitLength() > bits - 2)) {
		fail('sharedKeyRange', `sharedKey must satisfy 0 < s_i < m < n/4 (bitLength ${s.bitLength()} vs bits - 2 = ${bits - 2})`);
	}
	if (!inRangeCoprime(v, n) || jacobiSymbol(v, n) !== 1) {
		fail('verificationKeyRange', 'verificationKey v must be in (0, n), coprime to n and a quadratic residue (J(v|n) = 1)');
	}
	if (!inRangeCoprime(vi, n)) fail('verificationKeyShareRange', 'verificationKeyShare v_i must be in (0, n) and coprime to n');
	if (!inRangeCoprime(u, n)) fail('vkuRange', 'vku u must be in (0, n) and coprime to n');
	else if (jacobiSymbol(u, n) !== -1) fail('vkuJacobi', 'vku u must have Jacobi symbol -1 modulo n');

	if (checks.sharedKeyRange && checks.verificationKeyRange && checks.verificationKeyShareRange) {
		if (!v.modPow(s, n).equals(vi)) {
			fail('verificationKeyShare', 'verificationKeyShare does not equal v^sharedKey mod n: the share and its verification key do not belong together (wrong share, wrong v_i, or wrong v)');
		}
	}
	if (verificationKeys && options.shareIndex !== undefined && checks.shareIndexRange) {
		if (!verificationKeys[options.shareIndex - 1].equals(vi)) {
			fail('shareIndex', `verificationKeys[shareIndex - 1 = ${options.shareIndex - 1}] does not equal verificationKeyShare: shareIndex ${options.shareIndex} does not belong to this share`);
		}
	}

	let modulusHex = '', exponentHex = '';
	if (checks.modulusBits) {
		modulusHex = toCanonicalHex(n, bits);
		exponentHex = e.toString(16);
	}
	if (options.expectedPublicKey) {
		const expN = parseBigInteger(options.expectedPublicKey.n, 'expectedPublicKey.n');
		const expE = parseBigInteger(options.expectedPublicKey.e, 'expectedPublicKey.e');
		if (!expN.equals(n)) fail('expectedPublicKey', 'expectedPublicKey.n differs from publicKey.n');
		else if (options.expectedPublicKey.n.length !== bits / 4) {
			fail('expectedPublicKey', `expectedPublicKey.n hex width ${options.expectedPublicKey.n.length} != bits/4 = ${bits / 4}: the verifier requires signature width == modulus width`);
		}
		if (!expE.equals(e)) fail('expectedPublicKey', `expectedPublicKey.e (0x${expE.toString(16)}) differs from publicKey.e (0x${e.toString(16)})`);
	}

	const result: ShareConsistencyResult = {
		ok: failures.length === 0,
		failures,
		checks,
		bits,
		shareIndex: options.shareIndex,
		modulusHex,
		exponentHex,
	};
	if (!result.ok && options.throwOnFailure !== false) {
		throw new ShareConsistencyError(result);
	}
	return result;
}
