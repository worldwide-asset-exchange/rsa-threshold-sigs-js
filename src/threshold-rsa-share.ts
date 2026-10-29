import crypto from 'crypto';
import { hashTranscript, randomBigInt, BigInteger, parseBigInteger, modPowNative, assertModulusBits, digestToSigningInteger, applyJacobiLift, blindedModPow } from './utils';
import { PublicKey } from './threshold-rsa-key';
import { verifyShareConsistency, ShareConsistencyOptions, ShareConsistencyResult } from './share-consistency';

export type ThresholdRSAShareConfig = {
	bits: number;
	sharedKey: typeof BigInteger | string;
	publicKey: {
		n: typeof BigInteger | string;
		e: typeof BigInteger | string;
	};
	verificationKey: typeof BigInteger | string;
	verificationKeyShare: typeof BigInteger | string;
	vku: typeof BigInteger | string;
}

export type SigningOption = {
	pkcs1?: boolean;
	proof?: boolean;
}

function assertInOpenRange(x: typeof BigInteger, n: typeof BigInteger, label: string) {
	if (x.signum() <= 0 || x.compareTo(n) >= 0) {
		throw new Error(`${label} must be in (0, n)`);
	}
}

// Main class for Threshold Signatures
export class ThresholdRSAShare {
	private publicKey: PublicKey;
	private bits: number;
	private sharedKey: typeof BigInteger;
	private verificationKey: typeof BigInteger;
	private verificationKeyShare: typeof BigInteger;
	private vku: typeof BigInteger;
	private readonly config: ThresholdRSAShareConfig;

	constructor(config: ThresholdRSAShareConfig) {
		this.config = config;
		this.bits = config.bits;
		// Strict parsing (SIG-5) and structural checks (SIG-12) at construction. The
		// expensive share/verification-key binding check is `verifyConsistency()`.
		this.sharedKey = parseBigInteger(config.sharedKey, 'sharedKey');
		this.verificationKey = parseBigInteger(config.verificationKey, 'verificationKey');
		this.publicKey = {
			n: parseBigInteger(config.publicKey.n, 'publicKey.n'),
			e: parseBigInteger(config.publicKey.e, 'publicKey.e')
		};
		this.verificationKeyShare = parseBigInteger(config.verificationKeyShare, 'verificationKeyShare');
		this.vku = parseBigInteger(config.vku, 'vku');

		assertModulusBits(this.publicKey.n, this.bits);
		const { n } = this.publicKey;
		assertInOpenRange(this.sharedKey, n, 'sharedKey');
		assertInOpenRange(this.verificationKey, n, 'verificationKey');
		assertInOpenRange(this.verificationKeyShare, n, 'verificationKeyShare');
		assertInOpenRange(this.vku, n, 'vku');
		if (this.publicKey.e.compareTo(BigInteger.TWO) <= 0) {
			throw new Error('publicKey.e must be greater than 2');
		}
	}

	// Boot-time self-check: see verifyShareConsistency. Throws on mismatch unless
	// options.throwOnFailure === false.
	verifyConsistency(options: ShareConsistencyOptions = {}): ShareConsistencyResult {
		return verifyShareConsistency(this.config, options);
	}

	signMessage(message: string | Buffer, option: SigningOption = { pkcs1: true, proof: false }) {
		const msgHash = crypto.createHash('sha256').update(message).digest('hex');
		return this.signHash(msgHash, option);
	}

	// Generate signature shares for a message
	signHash(hash: typeof BigInteger | string, option: SigningOption = { pkcs1: true, proof: false }) {
		const { n, e } = this.publicKey;

		const pureMsgBigInt = parseBigInteger(hash, 'hash');
		const pkcs1 = option.pkcs1 === undefined || option.pkcs1 === null || option.pkcs1;
		const { x: msgBigIntToSign } = applyJacobiLift(digestToSigningInteger(pureMsgBigInt, this.bits, pkcs1), n, e, this.vku);

		// Generate signature shares: x_i = x~^(2 s_i) mod n, blinded (SIG-8)
		const exponent = this.sharedKey.shiftLeft(1);
		const signatureShare = blindedModPow(msgBigIntToSign, exponent, n);

		let proof;
		// Generate proofs of correctness for each share
		if (option.proof) {
			proof = this.generateProof(msgBigIntToSign, signatureShare);
		}

		return { signatureShare, proof, msgBigInt: pureMsgBigInt, msgBigIntToSign };
	}

	// Generate zero-knowledge proofs for signature shares
	generateProof(msgBigInt: typeof BigInteger, signatureShare: typeof BigInteger) {
		const { n } = this.publicKey;

		// Calculate lifted message x^4 mod n
		const xt = msgBigInt.modPow(new BigInteger('4'), n);

		// max random value for zero-knowledge proof 2^(Ln + 2*L1)
		const maxR = BigInteger.ONE.shiftLeft(this.bits + 256*2).subtract(BigInteger.ONE);
		// Random value for zero-knowledge proof
		// choose random integer less than maxR
		const r = randomBigInt(maxR);

		// Calculate proof components
		const vpBigInt = modPowNative(BigInt(this.verificationKey.toString()), BigInt(r.toString()), BigInt(n.toString()));
		const vp = new BigInteger(vpBigInt.toString());
		const xpBigInt = modPowNative(BigInt(xt.toString()), BigInt(r.toString()), BigInt(n.toString()));
		const xp = new BigInteger(xpBigInt.toString());

		// Challenge
		const c = hashTranscript({
			v: this.verificationKey,
			xt,
			vi: this.verificationKeyShare,
			xi2: signatureShare.modPow(new BigInteger('2'), n),
			vp,
			xp
		});

		// Response
		const z = (this.sharedKey.multiply(c)).add(r);

		return {z , c};
	}
}
