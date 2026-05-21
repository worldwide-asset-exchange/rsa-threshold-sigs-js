import crypto from 'crypto';
import { hashTranscript, randomBigInt, BigInteger, parseBigInteger, jacobiSymbol, emsaPkcs1v15encode, modPowNative } from './utils';
import { PublicKey } from './threshold-rsa-key';

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

// Main class for Threshold Signatures
export class ThresholdRSAShare {
	private publicKey: PublicKey;
	private bits: number;
	private sharedKey: typeof BigInteger;
	private verificationKey: typeof BigInteger;
	private verificationKeyShare: typeof BigInteger;
	private vku: typeof BigInteger;

	constructor(config: ThresholdRSAShareConfig) {
		this.bits = config.bits;
		this.sharedKey = parseBigInteger(config.sharedKey);
		this.verificationKey = parseBigInteger(config.verificationKey);
		this.publicKey = {
			n: parseBigInteger(config.publicKey.n),
			e: parseBigInteger(config.publicKey.e)
		};
		this.verificationKeyShare = parseBigInteger(config.verificationKeyShare);
		this.vku = parseBigInteger(config.vku);
	}

	signMessage(message: string | Buffer, option: SigningOption = { pkcs1: true, proof: false }) {
		const msgHash = crypto.createHash('sha256').update(message).digest('hex');
		return this.signHash(msgHash, option);
	}

	// Generate signature shares for a message
	signHash(hash: typeof BigInteger | string, option: SigningOption = { pkcs1: true, proof: false }) {
		const { n, e } = this.publicKey;

		// Convert message to BigInt if it's a string
		let pureMsgBigInt = parseBigInteger(hash);
		if (pureMsgBigInt.bitLength() > 256) {
			throw new Error('Message hash must be 256 bits or less');
		}

		let msgBigIntToSign = pureMsgBigInt;
		if (option.pkcs1 === undefined || option.pkcs1 === null || option.pkcs1) {
			const encodedPkcs1 = emsaPkcs1v15encode(Buffer.from(pureMsgBigInt.toString(16).padStart(64, '0'), 'hex'), this.bits);
			msgBigIntToSign = parseBigInteger(encodedPkcs1.toString('hex'));
		}

		if (jacobiSymbol(msgBigIntToSign, n) == -1) {
			msgBigIntToSign = msgBigIntToSign.multiply(this.vku.modPow(e, n)).mod(n);
		}

		// Generate signature shares
		const exponent = (new BigInteger('2')).multiply(this.sharedKey);
		// convert to native BigInt to calculate very large integer modPow, it two times fater than forge BigInteger
		const signatureShareBigInt = modPowNative(BigInt(msgBigIntToSign.toString()), BigInt(exponent.toString()), BigInt(n.toString()));
		const signatureShare = new BigInteger(signatureShareBigInt.toString());

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