import forge from "node-forge";
import crypto from 'crypto';

export const BigInteger = forge.jsbn.BigInteger;

Object.defineProperty(BigInteger, 'TWO', {
    get: function() {
        return new BigInteger('2');
    }
});

export const parseBigInteger = (value: typeof BigInteger | string) => {
	if (typeof value === 'string') {
		return new BigInteger(value, 16);
	}
	return value;
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
		const bytes = Buffer.from(forge.util.bytesToHex(forge.random.getBytesSync(numBytes)), 'hex');
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

// Hash a transcript (object) to create a challenge
export function hashTranscript(transcript: any) {
	let vBuf = Buffer.from(transcript.v.toByteArray());
	let xtBuf = Buffer.from(transcript.xt.toByteArray());
	let viBuf = Buffer.from(transcript.vi.toByteArray());
	let xi2Buf = Buffer.from(transcript.xi2.toByteArray());
	let vpBuf = Buffer.from(transcript.vp.toByteArray());
	let xpBuf = Buffer.from(transcript.xp.toByteArray());

	let size = vBuf.length + xtBuf.length + viBuf.length + xi2Buf.length + vpBuf.length + xpBuf.length;	

	const buff = Buffer.concat([vBuf, xtBuf, viBuf, xi2Buf, vpBuf, xpBuf], size);

	const hash = crypto.createHash('sha256')
							.update(buff)
							.digest('hex');
	return new BigInteger(hash, 16);
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