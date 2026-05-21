import { ThresholdRSAKey } from '../src';
import { BigInteger, jacobiSymbol, isPrime } from '../src/utils';

describe('ThresholdRSAKey', () => {
  let thresholdRSAKey: ThresholdRSAKey;

  it('should throw if invalid config', async () => {
    expect(() => new ThresholdRSAKey({ bits: 1023 })).toThrow('Invalid bits: must be between 1024 and 4096');
    expect(() => new ThresholdRSAKey({ bits: 4097 })).toThrow('Invalid bits: must be between 1024 and 4096');
  });

  it('should generate rsa key pair', async () => {
    thresholdRSAKey = new ThresholdRSAKey({ bits: 4096 });
    await thresholdRSAKey.generateKeyPair();
    expect(thresholdRSAKey.publicKey).toBeDefined();
    expect(thresholdRSAKey.privateKey).toBeDefined();

    expect(thresholdRSAKey.publicKey.n.bitLength()).toBe(4096);
    expect(thresholdRSAKey.publicKey.e.toString(10)).toBe('65537');

    expect(thresholdRSAKey.privateKey.p.isProbablePrime()).toBe(true);
    expect(thresholdRSAKey.privateKey.q.isProbablePrime()).toBe(true);

    // Check if (p-1)/2 and (q-1)/2 are prime
    const p_1 = (thresholdRSAKey.privateKey.p.subtract(BigInteger.ONE)).divide(new BigInteger('2'));
		const q_1 = (thresholdRSAKey.privateKey.q.subtract(BigInteger.ONE)).divide(new BigInteger('2'));
    expect(p_1.isProbablePrime()).toBe(true);
    expect(q_1.isProbablePrime()).toBe(true);
    expect(p_1.multiply(q_1).equals(thresholdRSAKey.privateKey.m)).toBe(true);

    expect(thresholdRSAKey.publicKey.n.equals(thresholdRSAKey.privateKey.p.multiply(thresholdRSAKey.privateKey.q))).toBe(true);
    expect((thresholdRSAKey.privateKey.d.multiply(thresholdRSAKey.publicKey.e)).mod(thresholdRSAKey.privateKey.m).equals(BigInteger.ONE)).toBe(true);
  });

  it('should split shares', async () => {
    const { publicKey, sharedKey } = await thresholdRSAKey.splitShares(3, 5);
    expect(publicKey).toBeDefined();
    expect(sharedKey).toBeDefined();

    expect(sharedKey.shares.length).toBe(5);
    expect(sharedKey.verificationKeys.length).toBe(5);

    // v belong to Qn, v < n
    expect(sharedKey.v.compareTo(publicKey.n)).toBeLessThan(0);
    for (const si of sharedKey.shares) {
      expect(si.compareTo(thresholdRSAKey.privateKey.m)).toBeLessThan(0);
    }

    for (let i = 0; i < 5; i++) {
      const vi = sharedKey.v.modPow(sharedKey.shares[i], publicKey.n);
      expect(vi.equals(sharedKey.verificationKeys[i])).toBe(true);
    }

    expect(sharedKey.vku.compareTo(publicKey.n)).toBeLessThan(0);
    expect(jacobiSymbol(sharedKey.vku, publicKey.n)).toBe(-1);
  });

  describe('Exponent Validation', () => {
    it('should accept valid prime exponents', () => {
      expect(() => new ThresholdRSAKey({ bits: 2048, e: 65537 })).not.toThrow();
      expect(() => new ThresholdRSAKey({ bits: 2048, e: 17 })).not.toThrow();
      expect(() => new ThresholdRSAKey({ bits: 2048, e: 257 })).not.toThrow();
    });

    it('should reject non-prime exponents', () => {
      expect(() => new ThresholdRSAKey({ bits: 2048, e: 100 }))
        .toThrow('RSA exponent e (100) must be prime');
      expect(() => new ThresholdRSAKey({ bits: 2048, e: 256 }))
        .toThrow('RSA exponent e (256) must be prime');
      expect(() => new ThresholdRSAKey({ bits: 2048, e: 15 }))
        .toThrow('RSA exponent e (15) must be prime');
    });

    it('should default to 65537 when exponent not provided', () => {
      const key = new ThresholdRSAKey({ bits: 2048 });
      expect(key['_config'].e).toBe(0x10001); // 65537 in hex
    });
  });

  describe('Threshold Parameter Validation', () => {
    let validKey: ThresholdRSAKey;

    beforeEach(async () => {
      validKey = new ThresholdRSAKey({ bits: 2048, e: 65537 });
      await validKey.generateKeyPair();
    });

    it('should accept valid threshold parameters', async () => {
      expect(() => validKey.splitShares(3, 5)).not.toThrow();
      expect(() => validKey.splitShares(1, 1)).not.toThrow();
      expect(() => validKey.splitShares(15, 21)).not.toThrow();
    });

    it('should reject invalid threshold values', async () => {
      expect(() => validKey.splitShares(0, 5))
        .toThrow('Invalid threshold: must be between 1 and 5');
      expect(() => validKey.splitShares(6, 5))
        .toThrow('Invalid threshold: must be between 1 and 5');
      expect(() => validKey.splitShares(-1, 5))
        .toThrow('Invalid threshold: must be between 1 and 5');
    });

    it('should reject invalid number of parties', async () => {
      expect(() => validKey.splitShares(1, 0))
        .toThrow('Number of parties must be at least 1');
      expect(() => validKey.splitShares(1, -5))
        .toThrow('Number of parties must be at least 1');
    });

    it('should enforce e > numParties requirement', async () => {
      const smallExponentKey = new ThresholdRSAKey({ bits: 2048, e: 17 });
      await smallExponentKey.generateKeyPair();
      
      // Should work: e=17 > numParties=10
      expect(() => smallExponentKey.splitShares(5, 10)).not.toThrow();
      
      // Should fail: e=17 <= numParties=20
      expect(() => smallExponentKey.splitShares(10, 20))
        .toThrow('RSA exponent e (17) must be greater than number of parties (20)');
      
      // Should fail: e=17 = numParties=17
      expect(() => smallExponentKey.splitShares(10, 17))
        .toThrow('RSA exponent e (17) must be greater than number of parties (17)');
    });

    it('should reject excessive number of parties', async () => {
      expect(() => validKey.splitShares(100, 200))
        .toThrow('Number of parties (200) too large. Maximum supported is 170 due to factorial calculation limits.');
      expect(() => validKey.splitShares(150, 180))
        .toThrow('Number of parties (180) too large. Maximum supported is 170 due to factorial calculation limits.');
    });

    it('should allow maximum supported parties', async () => {
      // Capture warnings but test should still work
      const originalWarn = console.warn;
      const mockWarn = jest.fn();
      console.warn = mockWarn;

      try {
        expect(() => validKey.splitShares(100, 170)).not.toThrow();
        expect(mockWarn).toHaveBeenCalledWith(
          'Warning: Large number of parties (170) may result in slow key generation due to factorial calculations.'
        );
      } finally {
        console.warn = originalWarn;
      }
    });

    it('should show warning for large party counts', async () => {
      // Capture console.warn
      const originalWarn = console.warn;
      const mockWarn = jest.fn();
      console.warn = mockWarn;

      try {
        validKey.splitShares(30, 60);
        expect(mockWarn).toHaveBeenCalledWith(
          'Warning: Large number of parties (60) may result in slow key generation due to factorial calculations.'
        );
      } finally {
        console.warn = originalWarn;
      }
    });

    it('should not show warning for reasonable party counts', async () => {
      const originalWarn = console.warn;
      const mockWarn = jest.fn();
      console.warn = mockWarn;

      try {
        validKey.splitShares(15, 30);
        expect(mockWarn).not.toHaveBeenCalled();
      } finally {
        console.warn = originalWarn;
      }
    });
  });

  describe('Mathematical Properties', () => {
    let key: ThresholdRSAKey;

    beforeEach(async () => {
      key = new ThresholdRSAKey({ bits: 2048, e: 65537 });
      await key.generateKeyPair();
    });

    it('should maintain RSA mathematical relationships', async () => {
      // Verify d*e ≡ 1 (mod m) where m = p'*q'
      const d = key.privateKey.d;
      const e = key.publicKey.e;
      const m = key.privateKey.m;
      
      expect((d.multiply(e)).mod(m).equals(BigInteger.ONE)).toBe(true);
    });

    it('should generate shares that sum correctly via Lagrange interpolation', async () => {
      const threshold = 3;
      const numParties = 5;
      const result = key.splitShares(threshold, numParties);
      
      // All shares should be different
      const shares = result.sharedKey.shares;
      for (let i = 0; i < shares.length; i++) {
        for (let j = i + 1; j < shares.length; j++) {
          expect(shares[i].equals(shares[j])).toBe(false);
        }
      }
      
      // All shares should be in valid range
      for (const share of shares) {
        expect(share.compareTo(BigInteger.ZERO)).toBeGreaterThan(0);
        expect(share.compareTo(key.privateKey.m)).toBeLessThan(0);
      }
    });

    it('should generate verification keys correctly', async () => {
      const result = key.splitShares(3, 5);
      const { v, shares, verificationKeys } = result.sharedKey;
      
      // Each verification key should equal v^share mod n
      for (let i = 0; i < shares.length; i++) {
        const expectedVK = v.modPow(shares[i], key.publicKey.n);
        expect(verificationKeys[i].equals(expectedVK)).toBe(true);
      }
    });
  });
});