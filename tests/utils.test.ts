import { emsaPkcs1v15encode, extendedGCD, generateSafePrime, hashTranscript, jacobiSymbol, lagrangeCoefficient, randomBigInt, randomBigIntCoprime, isPrime, safeFactorial, parseBigInteger, modPowNative } from '../src/utils';
import forge from 'node-forge';
import crypto from 'crypto';

describe('randomBigInt', () => {
  it('should generate a random BigInteger less than n', () => {
    for (let i = 0; i < 10; i++) {
      const n = new forge.jsbn.BigInteger('2').pow(1024)
      const result = randomBigInt(n);
      
      expect(result.bitLength()).toBeLessThanOrEqual(n.bitLength());
      expect(result.compareTo(n)).toBeLessThan(0);
    }
  });

  it('should generate a very large random BigInteger less than n', () => {
    const n = new forge.jsbn.BigInteger('2').pow(2**20)
    const result = randomBigInt(n);
    
    expect(result.bitLength()).toBeLessThanOrEqual(n.bitLength());
    expect(result.compareTo(n)).toBeLessThan(0);
  });
});

describe('hashTranscript', () => {
  it('should hash a transcript', () => {
    const transcript = {
      v: new forge.jsbn.BigInteger('10'),
      xt: new forge.jsbn.BigInteger('20'),
      vi: new forge.jsbn.BigInteger('30'),
      xi2: new forge.jsbn.BigInteger('40'),
      vp: new forge.jsbn.BigInteger('50'),
      xp: new forge.jsbn.BigInteger('60')
    };

    // Framing since 2.0.0 (SIG-11): sha256(tag || (len32be || bytes) for each element in order).
    // Expected value computed here independently of the implementation.
    const h = crypto.createHash('sha256').update(Buffer.from('waxio/rsa-threshold-signatures/shoup-proof/v2', 'utf8'));
    for (const x of [10, 20, 30, 40, 50, 60]) {
      const len = Buffer.alloc(4); len.writeUInt32BE(1, 0);
      h.update(len); h.update(Buffer.from([x]));
    }
    const result = hashTranscript(transcript);
    expect(result.toString(16).padStart(64, '0')).toBe(h.digest('hex'));
    // pre-2.0.0 unframed value, must no longer be produced
    expect(result.toString(16)).not.toBe('6e6db0c1e9357a0f1543a26d526d8548ae9867a4a64de41c2752e13f77bcfa13');
  });
});

describe('lagrangeCoefficient', () => {
  it('should calculate the Lagrange coefficient', () => {
    const s = [new forge.jsbn.BigInteger('1'), new forge.jsbn.BigInteger('2'), new forge.jsbn.BigInteger('3'), new forge.jsbn.BigInteger('4'), new forge.jsbn.BigInteger('5')];
    const delta = safeFactorial(new forge.jsbn.BigInteger('5'));
    const result = lagrangeCoefficient(s, forge.jsbn.BigInteger.ZERO, new forge.jsbn.BigInteger('3'), delta);
    expect(result.toString(10)).toBe('1200');

    const result1 = lagrangeCoefficient(s, forge.jsbn.BigInteger.ZERO, new forge.jsbn.BigInteger('2'), delta);
    expect(result1.toString(10)).toBe('-1200');
  });
});

describe('extendedGCD', () => {
  it('should calculate the extendedGCD', () => {
    const a = new forge.jsbn.BigInteger('102');
    const b = new forge.jsbn.BigInteger('38');
    const result = extendedGCD(a, b);
    expect(result[0].toString(10)).toBe('2');

    const a1 = new forge.jsbn.BigInteger('1023');
    const b1 = new forge.jsbn.BigInteger('38');
    const result1 = extendedGCD(a1, b1);
    expect(result1[0].toString(10)).toBe('1');
    expect(result1[1].multiply(a1).add(result1[2].multiply(b1)).toString(10)).toBe('1');
  });
});

describe('randomBigIntCoprime', () => {
  it('should generate a random BigInteger coprime with n', () => {
    const n1 = generateSafePrime(1024);
    const result1 = randomBigIntCoprime(n1);
    expect(result1.gcd(n1).toString(10)).toBe('1');

    const n2 = generateSafePrime(2048);
    const result2 = randomBigIntCoprime(n2);
    expect(result2.gcd(n2).toString(10)).toBe('1');
  });
});

describe('jacobiSymbol', () => {
  it('should calculate Jacobi symbol correctly', () => {
    // Test cases from known values
    expect(jacobiSymbol(new forge.jsbn.BigInteger('2'), new forge.jsbn.BigInteger('7'))).toBe(1);
    expect(jacobiSymbol(new forge.jsbn.BigInteger('10'), new forge.jsbn.BigInteger('7'))).toBe(-1);
    expect(jacobiSymbol(new forge.jsbn.BigInteger('10'), new forge.jsbn.BigInteger('15'))).toBe(0);
    expect(jacobiSymbol(new forge.jsbn.BigInteger('16'), new forge.jsbn.BigInteger('5'))).toBe(1);
    expect(jacobiSymbol(new forge.jsbn.BigInteger('16'), new forge.jsbn.BigInteger('5'))).toBe(1);
    expect(jacobiSymbol(new forge.jsbn.BigInteger('30'), new forge.jsbn.BigInteger('29'))).toBe(1);
  });

  it('should handle negative a values correctly', () => {
    // Test with negative a values
    expect(jacobiSymbol(new forge.jsbn.BigInteger('-2'), new forge.jsbn.BigInteger('7'))).toBe(-1);  // (-2/7) = (5/7) = -1
    expect(jacobiSymbol(new forge.jsbn.BigInteger('-3'), new forge.jsbn.BigInteger('7'))).toBe(1); // (-3/7) = (4/7) = 1
    expect(jacobiSymbol(new forge.jsbn.BigInteger('-4'), new forge.jsbn.BigInteger('7'))).toBe(-1);  // (-4/7) = (3/7) = 1
  });

  it('should handle large numbers', () => {
    const a = new forge.jsbn.BigInteger('1001');
    const n = new forge.jsbn.BigInteger('9907');
    const result = jacobiSymbol(a, n);
    expect(result).toBe(-1);

    const a1 = new forge.jsbn.BigInteger('1235');
    const n1 = new forge.jsbn.BigInteger('10007');
    const result1 = jacobiSymbol(a1, n1);
    expect(result1).toBe(-1);

    // large operands: compare with an independent native-BigInt Jacobi implementation
    const jacobiRef = (a: bigint, n: bigint): number => {
      a %= n; if (a < 0n) a += n;
      let r = 1;
      while (a !== 0n) {
        while ((a & 1n) === 0n) { a >>= 1n; const m8 = n % 8n; if (m8 === 3n || m8 === 5n) r = -r; }
        [a, n] = [n, a];
        if (a % 4n === 3n && n % 4n === 3n) r = -r;
        a %= n;
      }
      return n === 1n ? r : 0;
    };
    for (let i = 0; i < 20; i++) {
      const nHex = crypto.randomBytes(128).toString('hex');
      const nBig = BigInt('0x' + nHex) | 1n; // odd
      const aHex = crypto.randomBytes(32).toString('hex');
      const got = jacobiSymbol(new forge.jsbn.BigInteger(aHex, 16), new forge.jsbn.BigInteger(nBig.toString(16), 16));
      expect(got).toBe(jacobiRef(BigInt('0x' + aHex), nBig));
    }
  });

  it('should throw error for even n', () => {
    expect(() => jacobiSymbol(new forge.jsbn.BigInteger('2'), new forge.jsbn.BigInteger('8'))).toThrow();
  });

  it('should throw error for non-positive n', () => {
    expect(() => jacobiSymbol(new forge.jsbn.BigInteger('2'), new forge.jsbn.BigInteger('0'))).toThrow();
    expect(() => jacobiSymbol(new forge.jsbn.BigInteger('2'), new forge.jsbn.BigInteger('-7'))).toThrow();
  });

  it('should return 0 when a is 0', () => {
    expect(jacobiSymbol(new forge.jsbn.BigInteger('0'), new forge.jsbn.BigInteger('7'))).toBe(0);
  });
});

describe('emsaPkcs1v15encode', () => {
  it('should encode a message using EMSA-PKCS1-v1_5', () => {
    const message = 'Hello, world!';
    const hash = forge.md.sha256.create().update(message).digest().toHex();
    const result = emsaPkcs1v15encode(Buffer.from(hash, 'hex'), 4096);
    expect(result.toString('hex')).toBe('0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d060960864801650304020105000420315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3');
  });
});

describe('isPrime', () => {
  it('should correctly identify small prime numbers', () => {
    expect(isPrime(new forge.jsbn.BigInteger('2'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('3'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('5'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('7'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('11'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('17'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('97'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('257'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('65537'))).toBe(true);
  });

  it('should correctly identify small composite numbers', () => {
    expect(isPrime(new forge.jsbn.BigInteger('1'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('4'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('6'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('8'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('9'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('15'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('25'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('100'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('256'))).toBe(false);
  });

  it('should correctly identify larger prime numbers', () => {
    // Some larger known primes
    expect(isPrime(new forge.jsbn.BigInteger('1009'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('1013'))).toBe(true);
    expect(isPrime(new forge.jsbn.BigInteger('982451653'))).toBe(true);
  });

  it('should correctly identify larger composite numbers', () => {
    // Some larger known composites
    expect(isPrime(new forge.jsbn.BigInteger('1001'))).toBe(false); // 7 * 11 * 13
    expect(isPrime(new forge.jsbn.BigInteger('1023'))).toBe(false); // 3 * 11 * 31
    expect(isPrime(new forge.jsbn.BigInteger('982451654'))).toBe(false); // even number
  });

  it('should handle edge cases', () => {
    expect(isPrime(new forge.jsbn.BigInteger('0'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('-1'))).toBe(false);
    expect(isPrime(new forge.jsbn.BigInteger('-5'))).toBe(false);
  });

  it('should work with different k values (confidence levels)', () => {
    const number = new forge.jsbn.BigInteger('65537');
    
    // Test with different k values
    expect(isPrime(number, 1)).toBe(true);
    expect(isPrime(number, 5)).toBe(true);
    expect(isPrime(number, 20)).toBe(true);
    
    // Composite number should fail regardless of k
    const composite = new forge.jsbn.BigInteger('100');
    expect(isPrime(composite, 1)).toBe(false);
    expect(isPrime(composite, 10)).toBe(false);
  });
});

describe('safeFactorial', () => {
  it('should calculate small factorials correctly', () => {
    expect(safeFactorial(new forge.jsbn.BigInteger('0')).toString()).toBe('1');
    expect(safeFactorial(new forge.jsbn.BigInteger('1')).toString()).toBe('1');
    expect(safeFactorial(new forge.jsbn.BigInteger('5')).toString()).toBe('120');
    expect(safeFactorial(new forge.jsbn.BigInteger('10')).toString()).toBe('3628800');
  });

  it('should handle medium-sized factorials', () => {
    const result20 = safeFactorial(new forge.jsbn.BigInteger('20'));
    expect(result20.toString()).toBe('2432902008176640000');
    
    const result50 = safeFactorial(new forge.jsbn.BigInteger('50'));
    expect(result50.bitLength()).toBeGreaterThan(200);
    expect(result50.bitLength()).toBeLessThan(300);
  });

  it('should allow up to 170! (maximum safe value)', () => {
    expect(() => safeFactorial(new forge.jsbn.BigInteger('170'))).not.toThrow();
    const result170 = safeFactorial(new forge.jsbn.BigInteger('170'));
    expect(result170.bitLength()).toBeGreaterThan(1000);
  });

  it('should reject numbers larger than 170', () => {
    expect(() => safeFactorial(new forge.jsbn.BigInteger('171')))
      .toThrow('Factorial too large: 171! would exceed 8192 bits');
    expect(() => safeFactorial(new forge.jsbn.BigInteger('200')))
      .toThrow('Factorial too large: 200! would exceed 8192 bits');
    expect(() => safeFactorial(new forge.jsbn.BigInteger('1000')))
      .toThrow('Factorial too large: 1000! would exceed 8192 bits');
  });

  it('should respect custom bit limits', () => {
    // Test with smaller bit limit - 169! is about 1012 bits, so should exceed 1000
    expect(() => safeFactorial(new forge.jsbn.BigInteger('169'), 1000))
      .toThrow('Factorial calculation exceeded 1000 bits');
    
    // Test that smaller numbers still work with custom limit
    expect(() => safeFactorial(new forge.jsbn.BigInteger('10'), 1000)).not.toThrow();
    expect(() => safeFactorial(new forge.jsbn.BigInteger('165'), 1000)).not.toThrow(); // 165! = 983 bits < 1000
  });

  it('should handle bit length monitoring correctly', () => {
    // This test ensures the bit length check is working during calculation
    const result = safeFactorial(new forge.jsbn.BigInteger('100'));
    expect(result.bitLength()).toBeLessThan(8192); // Should be well under the limit
  });
});

describe('modPowNative', () => {
  it('should calculate modPow using native NodeJs BigInt', () => {
    const res1 = modPowNative(88n, 2n, 65n);
    expect(res1).toBe(9n);

    // random 4096-bit operands (no key material in fixtures)
    const base1 = BigInt('0x' + crypto.randomBytes(512).toString('hex'));
    const exponent1 = BigInt('0x' + crypto.randomBytes(512).toString('hex'));
    const n1 = BigInt('0x' + crypto.randomBytes(512).toString('hex')) | 1n;
    const res2 = modPowNative(base1, exponent1, n1);
    const res2Ref = parseBigInteger(base1.toString(16)).modPow(parseBigInteger(exponent1.toString(16)), parseBigInteger(n1.toString(16)));
    expect(res2.toString()).toBe(res2Ref.toString());
  });
});
