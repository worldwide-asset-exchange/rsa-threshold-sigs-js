import crypto from 'crypto';
import { extendedGCD, hashTranscript, lagrangeCoefficient, BigInteger, parseBigInteger, safeFactorial, assertModulusBits, digestToSigningInteger, applyJacobiLift, toCanonicalHex, kSubsets } from './utils';
import { PublicKey } from './threshold-rsa-key';

export type ThresholdRSAVerifierConfig = {
	threshold: number;
	numParties: number;
	bits: number;
	publicKey: {
		n: typeof BigInteger | string;
		e: typeof BigInteger | string;
	};
	verificationKey: typeof BigInteger | string;
	vku: typeof BigInteger | string;
	// Dealer-published per-party verification keys v_i (length numParties, index
	// i-1 for party i). Required for proof verification (verifySharesHash);
	// not needed for combining (verifySignatureHash). (SIG-1)
	verificationKeys?: (typeof BigInteger | string)[];
	// Upper bound on the number of k-subsets the combine tries before giving up
	// (default 256; 2-of-3 needs at most 3). (SIG-4)
	maxCombineAttempts?: number;
}

export type RSASignatureShare = {
	signatureShare: typeof BigInteger | string;
	proof?: {
		z: typeof BigInteger;
		c: typeof BigInteger;
	};
	// Deprecated since 1.4.0 and ignored: the verifier uses its configured
	// verificationKeys[shareIndex - 1] instead of a prover-supplied value (SIG-1).
	sharedVerificationKey?: typeof BigInteger;
	shareIndex: number;
}

export type RejectedShare = {
	position: number;    // index in the array the caller passed
	shareIndex: number;
	reason: string;
}

export type CombineResult = {
	signature: string;             // lower-case hex, exactly bits/4 wide, < n
	usedShareIndices: number[];    // the k-subset that verified
	rejectedShares: RejectedShare[]; // shares excluded before any subset was tried
	failedSubsets: number[][];     // share-index subsets tried before the one that verified
	suspectShareIndices: number[]; // indices that appear in failed subsets but not in the verified one
	attempts: number;
}

export type ShareProofFailure = {
	position: number;
	shareIndex: number;
	reason: string;
}

export type CombineErrorCode = 'NOT_ENOUGH_SHARES' | 'INVALID_SHARE' | 'NO_VALID_SUBSET';

export class CombineError extends Error {
	public readonly code: CombineErrorCode;
	public readonly rejectedShares: RejectedShare[];
	public readonly attemptedSubsets: number[][];
	constructor(code: CombineErrorCode, message: string, rejectedShares: RejectedShare[] = [], attemptedSubsets: number[][] = []) {
		super(message);
		this.name = 'CombineError';
		this.code = code;
		this.rejectedShares = rejectedShares;
		this.attemptedSubsets = attemptedSubsets;
	}
}

const DEFAULT_MAX_COMBINE_ATTEMPTS = 256;

// Main class for Threshold Signatures
export class ThresholdRSAVerifier {
	private threshold: number;
	private numParties: number;
	private bits: number;
	private publicKey: PublicKey;
	private delta: typeof BigInteger;
	private verificationKey: typeof BigInteger;
	private vku: typeof BigInteger;
	private verificationKeys?: typeof BigInteger[];
	private maxCombineAttempts: number;

	constructor(config: ThresholdRSAVerifierConfig) {
		this.threshold = config.threshold;
		this.numParties = config.numParties;
		this.bits = config.bits;
		this.publicKey = {
			n: parseBigInteger(config.publicKey.n, 'publicKey.n'),
			e: parseBigInteger(config.publicKey.e, 'publicKey.e')
		};
		this.verificationKey = parseBigInteger(config.verificationKey, 'verificationKey');
		this.vku = parseBigInteger(config.vku, 'vku');
		this.maxCombineAttempts = config.maxCombineAttempts ?? DEFAULT_MAX_COMBINE_ATTEMPTS;

		this.validateParams();
		assertModulusBits(this.publicKey.n, this.bits);

		if (config.verificationKeys !== undefined) {
			if (!Array.isArray(config.verificationKeys) || config.verificationKeys.length !== this.numParties) {
				throw new Error(`verificationKeys must be an array of length numParties (${this.numParties})`);
			}
			this.verificationKeys = config.verificationKeys.map((k, i) => parseBigInteger(k, `verificationKeys[${i}]`));
		}

		// Set delta = l! (factorial of total number of parties)
		this.delta = safeFactorial(new BigInteger(this.numParties.toString()));
	}

	validateParams() {
		if (!Number.isInteger(this.numParties) || this.numParties < 1) {
			throw new Error('Invalid numParties: must be a positive integer');
		}
		if (!Number.isInteger(this.threshold) || this.threshold < 1 || this.threshold > this.numParties) {
			throw new Error('Invalid threshold: must be between 1 and numParties');
		}
		if (!Number.isInteger(this.maxCombineAttempts) || this.maxCombineAttempts < 1) {
			throw new Error('Invalid maxCombineAttempts: must be a positive integer');
		}
	}

	private encodeAndLift(msgBigInt: typeof BigInteger | string, pkcs1: boolean) {
		const { n, e } = this.publicKey;
		return applyJacobiLift(digestToSigningInteger(msgBigInt, this.bits, pkcs1), n, e, this.vku);
	}

	verifySharesMessage(message: string | Buffer, sigShares: RSASignatureShare[], pkcs1: boolean = true) {
		const msgHash = crypto.createHash('sha256').update(message).digest('hex');
		return this.verifySharesHash(msgHash, sigShares, pkcs1);
	}

	// Verify signature shares and their proofs
	verifySharesHash(msgBigInt: typeof BigInteger | string, sigShares: RSASignatureShare[], pkcs1: boolean = true): boolean {
		return this.verifySharesHashDetailed(msgBigInt, sigShares, pkcs1).ok;
	}

	// Verify signature shares and their proofs, reporting which ones failed and why.
	// Requires `verificationKeys` in the verifier config: v_i is looked up by
	// shareIndex and any prover-supplied `sharedVerificationKey` is ignored (SIG-1).
	verifySharesHashDetailed(msgBigInt: typeof BigInteger | string, sigShares: RSASignatureShare[], pkcs1: boolean = true): { ok: boolean, failures: ShareProofFailure[] } {
		if (!this.verificationKeys) {
			throw new Error('verifySharesHash requires the dealer-published verificationKeys in the verifier config');
		}
		const { n } = this.publicKey;
		const { x: msgBigIntToSign } = this.encodeAndLift(msgBigInt, pkcs1);

		// Reject an empty share set: an empty loop would otherwise return true
		// vacuously, which a caller using this as a gate could misread as success.
		if (sigShares.length === 0) {
			return { ok: false, failures: [{ position: -1, shareIndex: -1, reason: 'empty share set' }] };
		}

		// Calculate lifted message
		const xt = msgBigIntToSign.modPow(new BigInteger('4'), n);
		const failures: ShareProofFailure[] = [];

		for (let i = 0; i < sigShares.length; i++) {
			const share = sigShares[i];
			const idx = share.shareIndex;
			const fail = (reason: string) => failures.push({ position: i, shareIndex: idx, reason });
			if (!Number.isInteger(idx) || idx < 1 || idx > this.numParties) { fail(`invalid share index ${idx}`); continue; }
			if (!share.proof || share.proof.z === undefined || share.proof.c === undefined) { fail('missing proof'); continue; }
			let xi: typeof BigInteger;
			try { xi = parseBigInteger(share.signatureShare, 'signatureShare'); } catch (e) { fail((e as Error).message); continue; }
			if (xi.signum() <= 0 || xi.compareTo(n) >= 0 || !xi.gcd(n).equals(BigInteger.ONE)) { fail('signature share not in (0, n) or not coprime to n'); continue; }
			const { z, c } = share.proof;
			const vi = this.verificationKeys[idx - 1];

			// Verify proof components
			const vp1 = this.verificationKey.modPow(z, n);
			// vi ^ (-c)
			const vp2 = vi.modPow(c, n).modInverse(n);
			const vp = (vp1.multiply(vp2)).mod(n);

			const xp1 = xt.modPow(z, n);
			const xp2 = xi.modPow((new BigInteger('2')).multiply(c), n).modInverse(n);
			const xp = (xp1.multiply(xp2)).mod(n);

			// Calculate expected challenge
			const expectedC = hashTranscript({
				v: this.verificationKey,
				xt,
				vi,
				xi2: xi.modPow(new BigInteger('2'), n),
				vp,
				xp
			});

			// Verify challenge
			if (!c.equals(expectedC)) {
				fail('proof challenge mismatch');
			}
		}

		return { ok: failures.length === 0, failures };
	}

	verifySignatureMessage(message: string | Buffer, shares: RSASignatureShare[], pkcs1: boolean = true): string {
		return this.combineSignatureMessage(message, shares, pkcs1).signature;
	}

	// Reconstruct full signature from shares
	verifySignatureHash(msgBigInt: typeof BigInteger | string, shares: RSASignatureShare[], pkcs1: boolean = true): string {
		return this.combineSignatureHash(msgBigInt, shares, pkcs1).signature;
	}

	combineSignatureMessage(message: string | Buffer, shares: RSASignatureShare[], pkcs1: boolean = true): CombineResult {
		const msgHash = crypto.createHash('sha256').update(message).digest('hex');
		return this.combineSignatureHash(msgHash, shares, pkcs1);
	}

	// Reconstruct the full signature from shares, trying k-subsets until one
	// verifies (SIG-4), after rejecting every partial that is not in (0, n) and
	// coprime to n (SIG-13: a zero partial used to reach modInverse(0)).
	combineSignatureHash(msgBigInt: typeof BigInteger | string, shares: RSASignatureShare[], pkcs1: boolean = true): CombineResult {
		const { n, e } = this.publicKey;

		// Verify we have enough shares
		if (shares.length < this.threshold) {
			throw new CombineError('NOT_ENOUGH_SHARES', 'Not enough shares to reconstruct signature');
		}

		const { x: msgBigIntToSign, lifted: vkuMutiple } = this.encodeAndLift(msgBigInt, pkcs1);

		// Structural checks over the WHOLE provided set (malformed input → throw):
		// index range and duplicates. An out-of-range index would produce an
		// incorrect Lagrange coefficient; a duplicate could reach the threshold
		// count by reusing a single party's share.
		const shareIndices = shares.map(share => share.shareIndex);
		for (const idx of shareIndices) {
			if (!Number.isInteger(idx) || idx < 1 || idx > this.numParties) {
				throw new Error(`Invalid share index ${idx}: must be an integer between 1 and ${this.numParties}`);
			}
		}
		if (new Set(shareIndices).size !== shareIndices.length) {
			throw new Error('Duplicate share indices detected');
		}

		// Value checks per share (bad value → reject that share, keep the rest).
		const candidates: { position: number, shareIndex: number, value: typeof BigInteger }[] = [];
		const rejectedShares: RejectedShare[] = [];
		shares.forEach((share, position) => {
			const value = parseBigInteger(share.signatureShare, `shares[${position}].signatureShare`);
			let reason: string | undefined;
			if (value.signum() <= 0) reason = value.signum() === 0 ? 'zero' : 'negative';
			else if (value.compareTo(n) >= 0) reason = 'not less than n';
			else if (!value.gcd(n).equals(BigInteger.ONE)) reason = 'not coprime to n';
			if (reason) rejectedShares.push({ position, shareIndex: share.shareIndex, reason });
			else candidates.push({ position, shareIndex: share.shareIndex, value });
		});
		const describeRejected = () => rejectedShares.map(r => `index ${r.shareIndex} at position ${r.position} (${r.reason})`).join(', ');
		if (candidates.length < this.threshold) {
			throw new CombineError('INVALID_SHARE',
				`Signature share(s) rejected before combine: ${describeRejected()}; only ${candidates.length} valid share(s) remain for threshold ${this.threshold}`,
				rejectedShares);
		}

		const ePrime = new BigInteger('4');
		const msgVerify = msgBigIntToSign.modPow(ePrime, n);
		const attemptedSubsets: number[][] = [];
		let attempts = 0;
		let capped = false;

		for (const subset of kSubsets(candidates.length, this.threshold)) {
			if (attempts >= this.maxCombineAttempts) { capped = true; break; }
			attempts++;
			const selected = subset.map(i => candidates[i]);
			const indices = selected.map(s => s.shareIndex);
			const w = this.lagrangeCombine(selected);

			// Verify intermediate result: w^e == x~^4
			if (!w.modPow(e, n).equals(msgVerify)) {
				attemptedSubsets.push(indices);
				continue;
			}

			const signature = this.finalizeSignature(w, msgBigIntToSign, vkuMutiple);
			const used = new Set(indices);
			const suspects = Array.from(new Set(attemptedSubsets.flat())).filter(i => !used.has(i)).sort((a, b) => a - b);
			return {
				signature,
				usedShareIndices: indices,
				rejectedShares,
				failedSubsets: attemptedSubsets,
				suspectShareIndices: suspects,
				attempts,
			};
		}

		const indexList = candidates.map(c => c.shareIndex).join(', ');
		throw new CombineError('NO_VALID_SUBSET',
			`No ${this.threshold}-subset of the ${candidates.length} valid share(s) (indices [${indexList}]) produced a valid signature after ${attempts} attempt(s)` +
			(capped ? ` (attempt cap ${this.maxCombineAttempts} reached)` : '') +
			`; subsets tried: ${attemptedSubsets.map(s => `[${s.join(', ')}]`).join(' ')}` +
			(rejectedShares.length ? `; rejected before combine: ${describeRejected()}` : ''),
			rejectedShares, attemptedSubsets);
	}

	// w = ∏ x_i^(2 λ_i) mod n over the selected k shares (= x~^(4d) when all are honest)
	private lagrangeCombine(selected: { shareIndex: number, value: typeof BigInteger }[]): typeof BigInteger {
		const { n } = this.publicKey;
		const shareIndicesBigInt = selected.map(share => new BigInteger(share.shareIndex.toString()));
		let w = BigInteger.ONE;
		for (const share of selected) {
			const lagrangeCoeff = lagrangeCoefficient(shareIndicesBigInt, BigInteger.ZERO, new BigInteger(share.shareIndex.toString()), this.delta);
			const exponent = lagrangeCoeff.multiply(new BigInteger('2'));
			// share.value is in (0, n) and coprime to n, so modInverse is defined.
			let part = share.value.modPow(exponent.abs(), n);
			if (exponent.compareTo(BigInteger.ZERO) < 0) {
				part = part.modInverse(n);
			}
			w = (w.multiply(part)).mod(n);
		}
		return w;
	}

	// y = w^a · x~^b with 4a + eb = 1, so y^e = x~; divide u back out if lifted; canonical hex.
	private finalizeSignature(w: typeof BigInteger, msgBigIntToSign: typeof BigInteger, vkuMutiple: boolean): string {
		const { n, e } = this.publicKey;
		const ePrime = new BigInteger('4');

		// Calculate Bezout coefficients for e' and e
		const [gcd, bezoutA, bezoutB] = extendedGCD(ePrime, e);

		if (!gcd.equals(BigInteger.ONE)) {
			throw new Error('Verify signature can not find Bezout coefficients');
		}

		// Convert w to the final signature
		let p1 = w.modPow(bezoutA.abs(), n);
		if (bezoutA.compareTo(BigInteger.ZERO) < 0) {
			p1 = p1.modInverse(n);
		}
		let p2 = msgBigIntToSign.modPow(bezoutB.abs(), n);
		if (bezoutB.compareTo(BigInteger.ZERO) < 0) {
			p2 = p2.modInverse(n);
		}
		let signature = (p1.multiply(p2)).mod(n);

		// Verify final signature
		const signatureVerification = signature.modPow(e, n);

		if (!signatureVerification.equals(msgBigIntToSign)) {
			throw new Error('Combine signature is invalid');
		}
		// page 218
		// The original share combination algorithm produces y such that y^e = x.
		// If x = x~uˆe, then we can divide y by u, obtaining an eth root of H(M)
		// so we still obtain a standard RSA signature.
		if (vkuMutiple) {
			const vkuInv = this.vku.modInverse(n);
			signature = signature.multiply(vkuInv).mod(n);
		}
		// Lower-case hex padded with leading zeros to exactly bits/4 characters
		return toCanonicalHex(signature, this.bits);
	}
}
