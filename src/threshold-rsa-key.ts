import { randomBigInt, BigInteger, generateSafePrime, randomBigIntCoprime, jacobiSymbol, isPrime, safeFactorial } from './utils';

export type ThresholdRSAKeyConfig = {
	bits: number,
	e?: number
}

export type PublicKey = {
	n: typeof BigInteger,
	e: typeof BigInteger
}

export type PrivateKey = {
	p: typeof BigInteger,
	q: typeof BigInteger,
	d: typeof BigInteger,
	m: typeof BigInteger,
	dmp1: typeof BigInteger,
	dmq1: typeof BigInteger,
	coeff: typeof BigInteger
}

export type Share = {
	shares: typeof BigInteger[],
	verificationKeys: typeof BigInteger[],
	v: typeof BigInteger,
	vku: typeof BigInteger
}

// Main class for Threshold Signatures
export class ThresholdRSAKey {
	private _config: ThresholdRSAKeyConfig;
	private _publicKey: PublicKey;
	private _privateKey: PrivateKey;

	constructor(config: ThresholdRSAKeyConfig) {
		this._config = config;
		this.validateParams();
	}

	get publicKey() {
		return this._publicKey;
	}

	get privateKey() {
		return this._privateKey;
	}

	validateParams() {
		if (!this._config.bits || this._config.bits < 1024 || this._config.bits > 4096) {
			throw new Error('Invalid bits: must be between 1024 and 4096');
		}

		if (this._config.e) {
			// Shoup's paper requires e > l (number of parties)
			const e = new BigInteger(this._config.e.toString(), 10);

			// Verify e is prime (required by Shoup's protocol)
			if (!isPrime(e)) {
				throw new Error(`RSA exponent e (${this._config.e}) must be prime`);
			}
		} else {
			this._config.e = 0x10001;
		}
	}

	// Validate parameters for threshold scheme
	validateThresholdParams(threshold: number, numParties: number) {
		// Check numParties first
		if (numParties < 1) {
			throw new Error('Number of parties must be at least 1');
		}

		// Basic threshold validation
		if (threshold < 1 || threshold > numParties) {
			throw new Error(`Invalid threshold: must be between 1 and ${numParties}`);
		}

		const e = new BigInteger(this._config.e.toString(), 10);
		if (e.compareTo(new BigInteger(numParties.toString())) <= 0) {
			throw new Error(`RSA exponent e (${this._config.e}) must be greater than number of parties (${numParties})`);
		}

		// Practical limit check for factorial calculation
		if (numParties > 170) {
			throw new Error(`Number of parties (${numParties}) too large. Maximum supported is 170 due to factorial calculation limits.`);
		}

		// Additional warning for large party counts
		if (numParties > 50) {
			console.warn(`Warning: Large number of parties (${numParties}) may result in slow key generation due to factorial calculations.`);
		}
	}

	// Generate RSA key pair and shares
	async generateKeyPair() {
		// Generate RSA key pair
		const p = generateSafePrime(Math.ceil(this._config.bits / 2));
		let q;
		do {
			q = generateSafePrime(Math.floor(this._config.bits / 2));
		} while (p.equals(q));

		const n = p.multiply(q);
		const e = new BigInteger(this._config.e.toString(), 10);

		// Calculate m = (p-1)(q-1)/2 for safe primes (using m = φ(n)/2)
		const m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)).divide(new BigInteger('4'));

		// Calculate private key d = e^(-1) mod m
		const d = e.modInverse(m);

		// Public key
		this._publicKey = { n, e };

		const dmp1 = d.mod(p.subtract(BigInteger.ONE));
    const dmq1 = d.mod(q.subtract(BigInteger.ONE));
    const coeff = q.modInverse(p);

		// Private key (unshared)
		this._privateKey = { p, q, d, m, dmp1, dmq1, coeff };
	}

	splitShares(threshold: number, numParties: number): { publicKey: PublicKey, sharedKey: Share, bits: number, threshold: number, numParties: number } {
		if (this._publicKey === undefined) {
			throw new Error('Please generate a key pair first');
		}

		// Validate threshold parameters
		this.validateThresholdParams(threshold, numParties);

		const delta = safeFactorial(new BigInteger(numParties.toString()));
		const deltaInv = delta.modInverse(this._privateKey.m);

		const vku = this.generateVerificationUParameter(this._publicKey.n);

		// Generate verification key
		// choose random coprime with n
		const v_pre = randomBigIntCoprime(this._publicKey.n);
		// find ramdom quadratic residues of n
		const v = v_pre.modPowInt(2, this._publicKey.n);

		// Split the private key using Shamir's Secret Sharing
		const shares = this.splitShamir(
			threshold,
			numParties,
			deltaInv
		);

		// Generate verification keys for each share
		const verificationKeys = [];
		for (let i = 0; i < shares.length; i++) {
			verificationKeys.push(v.modPow(shares[i], this._publicKey.n));
		}

		// Store shared key information
		const sharedKey: Share = {
			shares,
			v,
			vku,
			verificationKeys
		};

		return { publicKey: this._publicKey, sharedKey, bits: this._config.bits, threshold, numParties };
	}

	// Create Shamir secret shares
	// default deltaInv is 1 that means protocol 1
	splitShamir(threshold: number, numParties: number, deltaInv: typeof BigInteger = BigInteger.ONE) {
		// Polynomial coefficients: [secret, random, random, ...]
		const a = [this._privateKey.d];

		// Generate random coefficients for the polynomial
		for (let i = 1; i < threshold; i++) {
			const randomCoeff = randomBigInt(this._privateKey.m.subtract(BigInteger.ONE));
			a.push(randomCoeff);
		}

		// Generate shares by evaluating the polynomial at points 1, 2, ..., numShares
		const shares = [];
		for (let i = 1; i <= numParties; i++) {
			let si = this.evaluatePolynomial(a, new BigInteger(i.toString(), 10), this._privateKey.m);
			si = si.multiply(deltaInv).mod(this._privateKey.m);
			shares.push(si);
		}

		return shares;
	}

	// Evaluate polynomial at point x
	evaluatePolynomial(poly: typeof BigInteger[], x: typeof BigInteger, m: typeof	BigInteger) {
		let result = BigInteger.ZERO;
		let xPow = BigInteger.ONE;

		for (let i = 0; i < poly.length; i++) {
			// Calculate term = (poly[i] * xPow) mod m
			const term = (poly[i].multiply(xPow)).mod(m);
			// Add term to result and take modulo m
			result = (result.add(term)).mod(m);
			// Calculate next power of x
			xPow = (xPow.multiply(x)).mod(m);
		}

		return result;
	}

	// safe parameter for protocol 2 
	generateVerificationUParameter(n: typeof BigInteger) {
		let vku: typeof BigInteger;
		do {
			vku = randomBigIntCoprime(n);
		} while (jacobiSymbol(vku, n) !== -1);

		return vku;
	}
}