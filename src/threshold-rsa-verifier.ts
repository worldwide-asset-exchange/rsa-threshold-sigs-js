import crypto from 'crypto';
import { extendedGCD, hashTranscript, lagrangeCoefficient, BigInteger, parseBigInteger, jacobiSymbol, emsaPkcs1v15encode, safeFactorial } from './utils';
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
}

export type RSASignatureShare = {
	signatureShare: typeof BigInteger;
	proof: {
		z: typeof BigInteger;
		c: typeof BigInteger;
	};
	sharedVerificationKey: typeof BigInteger;
	shareIndex: number;
}

// Main class for Threshold Signatures
export class ThresholdRSAVerifier {
	private threshold: number;
	private numParties: number;
	private bits: number;
	private publicKey: PublicKey;
	private delta: typeof BigInteger;
	private verificationKey: typeof BigInteger;
	private vku: typeof BigInteger;

	constructor(config: ThresholdRSAVerifierConfig) {
		this.threshold = config.threshold;
		this.numParties = config.numParties;
		this.bits = config.bits;
		this.publicKey = {
			n: parseBigInteger(config.publicKey.n),
			e: parseBigInteger(config.publicKey.e)
		};
		this.verificationKey = parseBigInteger(config.verificationKey);
		this.vku = parseBigInteger(config.vku);

		this.validateParams();

		// Set delta = l! (factorial of total number of parties)
		this.delta = safeFactorial(new BigInteger(this.numParties.toString()));
	}

	validateParams() {
		if (this.threshold < 1 || this.threshold > this.numParties) {
			throw new Error('Invalid threshold: must be between 1 and numParties');
		}
	}

	verifySharesMessage(message: string, sigShares: RSASignatureShare[], pkcs1: boolean = true) {
		const msgHash = crypto.createHash('sha256').update(message).digest('hex');
		return this.verifySharesHash(msgHash, sigShares, pkcs1);
	}

	// Verify signature shares and their proofs
	verifySharesHash(msgBigInt: typeof BigInteger | string, sigShares: RSASignatureShare[], pkcs1: boolean = true) {
		const { n, e } = this.publicKey;;
		const delta = this.delta;

		let msgBigIntToSign = parseBigInteger(msgBigInt);
		if (pkcs1) {
			const encodedPkcs1 = emsaPkcs1v15encode(Buffer.from(msgBigIntToSign.toString(16), 'hex'), this.bits);
			msgBigIntToSign = parseBigInteger(encodedPkcs1.toString('hex'));
		}
		if (jacobiSymbol(msgBigIntToSign, n) == -1) {
			msgBigIntToSign = msgBigIntToSign.multiply(this.vku.modPow(e, n)).mod(n);
		}

		// Reject an empty share set: an empty loop would otherwise return true
		// vacuously, which a caller using this as a gate could misread as success.
		if (sigShares.length === 0) {
			return false;
		}

		// Calculate lifted message
		const xt = msgBigIntToSign.modPow(new BigInteger('4'), n);

		// Verify each proof
		for (let i = 0; i < sigShares.length; i++) {
			const { z, c } = sigShares[i].proof;

			// Verify proof components
			const vp1 = this.verificationKey.modPow(z, n);
			// vi ^ (-c)
			const vp2 = sigShares[i].sharedVerificationKey.modPow(c, n).modInverse(n);
			const vp = (vp1.multiply(vp2)).mod(n);

			const xp1 = xt.modPow(z, n);
			const xp2 = sigShares[i].signatureShare.modPow((new BigInteger('2')).multiply(c), n).modInverse(n);
			const xp = (xp1.multiply(xp2)).mod(n);

			// Calculate expected challenge
			const expectedC = hashTranscript({
				v: this.verificationKey,
				xt,
				vi: sigShares[i].sharedVerificationKey,
				xi2: sigShares[i].signatureShare.modPow(new BigInteger('2'), n),
				vp,
				xp
			});

			// Verify challenge
			if (!c.equals(expectedC)) {
				return false;
			}
		}

		return true;
	}

	verifySignatureMessage(message: string | Buffer, shares: RSASignatureShare[], pkcs1: boolean = true) {
		const msgHash = crypto.createHash('sha256').update(message).digest('hex');
		return this.verifySignatureHash(msgHash, shares, pkcs1);
	}

	// Reconstruct full signature from shares
	verifySignatureHash(msgBigInt: typeof BigInteger | string, shares: RSASignatureShare[], pkcs1: boolean = true): string {
		const { n, e } = this.publicKey;
		const delta = this.delta;

		// Verify we have enough shares
		if (shares.length < this.threshold) {
			throw new Error('Not enough shares to reconstruct signature');
		}

		let msgBigIntToSign = parseBigInteger(msgBigInt);
		if (pkcs1) {
			const encodedPkcs1 = emsaPkcs1v15encode(Buffer.from(msgBigIntToSign.toString(16).padStart(64, '0'), 'hex'), this.bits);
			msgBigIntToSign = parseBigInteger(encodedPkcs1.toString('hex'));
		}

		let vkuMutiple = false;
		if (jacobiSymbol(msgBigIntToSign, n) == -1) {
			msgBigIntToSign = msgBigIntToSign.multiply(this.vku.modPow(e, n)).mod(n);
			vkuMutiple = true;
		}

		// Only use up to threshold shares if more provided
		const selectedShares = shares.slice(0, this.threshold);

		// Validate share indices are within the valid range [1, numParties].
		// An out-of-range index (e.g. 0) would produce an incorrect Lagrange
		// coefficient and must not be silently accepted.
		const shareIndices = selectedShares.map(share => share.shareIndex);
		for (const idx of shareIndices) {
			if (!Number.isInteger(idx) || idx < 1 || idx > this.numParties) {
				throw new Error(`Invalid share index ${idx}: must be an integer between 1 and ${this.numParties}`);
			}
		}

		// Check for duplicate share indices (prevents reaching the threshold
		// count by reusing a single party's share).
		if (new Set(shareIndices).size !== shareIndices.length) {
			throw new Error('Duplicate share indices detected');
		}

		// Combine signature shares using Lagrange interpolation
		let w = BigInteger.ONE;
		const shareIndicesBigInt = selectedShares.map(share => new BigInteger(share.shareIndex.toString()));
		for (let i = 0; i < selectedShares.length; i++) {
			const share = selectedShares[i];

			// Calculate Lagrange coefficient
			const lagrangeCoeff = lagrangeCoefficient(shareIndicesBigInt, BigInteger.ZERO, new BigInteger(share.shareIndex.toString()), this.delta);

			const exponent = lagrangeCoeff.multiply(new BigInteger('2'));

			let part = share.signatureShare.modPow(exponent.abs(), n);
			if (exponent.compareTo(BigInteger.ZERO) < 0) {
				part = part.modInverse(n);
			}
			w = (w.multiply(part)).mod(n);
		}

		// Calculate e' = 4
		const ePrime = new BigInteger('4');

		// Verify intermediate result
		const wVerify = w.modPow(e, n);
		const msgVerify = msgBigIntToSign.modPow(ePrime, n);

		if (!wVerify.equals(msgVerify)) {
			throw new Error('Intermediate verify signature is invalid');
		}

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

		if (signatureVerification.equals(msgBigIntToSign)) {
			// page 218
			// The original share combination algorithm produces y such that y^e = x.
			// If x = x~uˆe, then we can divide y by u, obtaining an eth root of H(M)
			// so we still obtain a standard RSA signature.
			if (vkuMutiple) {
				const vkuInv = this.vku.modInverse(n);
				signature = signature.multiply(vkuInv).mod(n);
			}
			// Convert signature to hex and pad with leading zeros to ensure 256 characters
			const signatureHex = signature.toString(16);
			const paddedSignature = signatureHex.padStart(this.bits/4, '0');
			return paddedSignature;
		} else {
			throw new Error('Combine signature is invalid');
		}
	}
}