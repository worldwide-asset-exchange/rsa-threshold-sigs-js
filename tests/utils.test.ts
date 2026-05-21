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

    const result = hashTranscript(transcript);
    expect(result.toString(16)).toBe('6e6db0c1e9357a0f1543a26d526d8548ae9867a4a64de41c2752e13f77bcfa13');
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

    const a2 = new forge.jsbn.BigInteger('FED9EFBD5A8EF6820D639DBCB831DAF9D6308312CC73D6188BEB54A9A148E29A', 16);
    const n2 = new forge.jsbn.BigInteger('63baca880eade29f1490a070d147cf2f7108316eda444c88c5850f730e9a465cc251e49595e9bbcd320814a692b0812291e3345445cd3068e92d4309b8d2f05477fb69df81bab294001a9c9c070982f1af0d02ff1d4ce3a482f789bc34a2aabf91c1c84e32641e5c291f9d3bb159b62125e011c554a5060d9c6f632945303df585d0cd3322e401410061615036f2d5e8374d457f30fddaaa0f726a4732294a64c52140c94a5388054a83c8944669b0e314466f8d586a6cd954df6770d5c4278902d94de66bdc1c79d6b876bde5558c046e9efb447add81ab45eda5041cd5dce439c8d02b2cfaae483c3d011e186677c7ad504c207f69008fb342e2bfe3f0ca0c858fe4bb8618000cffe9f392200bd8f8dffaeb59c4ea051a3178d9f2fb7745f90d9b509939d3cdbe54745a910af5608bbf52b7982c03467e511f3bf6b41d0ecaed2043af7d83cfb9c5b0d709de7aa023c7adff1fbb0597c12078b15a821a2023ff33e90a4f67b36954ca0782e2972a2d4af48acd063abad90b877fa1a7a02e976d88d543584a7af05dea9c0febfd435749cdde4ccd57b3f63a3afe259d49d15afa64d0304ea36a0b79191f0f595feb6f78f33ff097f617df23674782c15e57d6f74564de61bb6c7b90d09ddcc881315f2057e6e6789adcdc682bbe2e972dab41d74f3c754cc492cb4c01940967dba07020550d5ffb43d91ef25c2c608a0ac335', 16);
    const result2 = jacobiSymbol(a2, n2);
    expect(result2).toBe(1);
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

    const base1 = BigInt('0xa9db737359a33726b9338006725a116083b2eac503cd595d38176cec3c9aecc21c5dbe9ad15ee1b807d0cba555f57a58757919dc2d2a08f9e6647b536fbacb8473a7a82a9d92899997dec1ab844e9ff2147b34f7f9984f28a071a9aba9b1650db689d1542a5178ed53bba25e102b1517655333f354b5a251a5c67212ab2b193c4c4fec8fd9fc24feac9a3dde8aa355717711a267cadeebbbc823f2242a71662b6cdf9e615f0ca094593227a2bb2332cc2560c5c5d3812a9ce1f08a5f977baf2495ed990f09d2cff1d75ece396431a7be0db73d9934bc63b09baf27ed586f3776169e4fb8bec591e858e1ce1b93df3f2996607b0580023927dccfff87adaef09fe23efa2928214f045abe66480be68139d3d44a9d21b5ad3440de0a73be9ef469104ddc5cbdd6bf59b5a692145c530d69899b34296289e5515265c7c9ad89eb49d18f4a1a5dd89d25276824092629e5dbfb40b3b953d3d67199048d30f48360a1235e8076a07c5183f5200d0e8011384d4839af5b890c30ce688cd1f223404979b43af23268b0085b55c5ef3f6872a55b82e0ece2ddddc62b05eca58bdb0abb31fd1b843553c167d9f8872d553af0133e7a65db04545d7b96b8ccda32f325b2bf421cebd9f7c7c67374df23da016d8cb6c5271308107ad41f97e1544a6b05eeba1e639c687b27fdcea667ab6bdafae62db9cf6d85df4584c0b735eee28d42c925');
    const exponent1 = BigInt('0xafa4d31c69e791432ff8f7615c3b166cb2608c63784676654dc9266dfd5c285935880a79a07bd536b81796c1f09e8f308d8b695c83b01be65e08077235144829958231477592d0921324d89b08ff6a05d065aedfd18358799b3934bf4c8dd1831c536226a161c18422714425582d205bda2c84bdc5128966ac351c2b3ed4d6d17dadb8ef3f9052039b7a125edad33fd0819a57c6716ecb48a6297e1bc6a90ac6deb6bb9bd73cf1530eceeadb01b78ba1813ef9103d183140ed36a422bad571cbfef051bd99de319cdfbd120cb974c5f27fa344b412a25269a747f8224ee8227db1eec91b311920e205564f703ad558bfec8be9867f80a940e0954f4ae01e637b5fa93b820de864b07de1b532774bee81f966bfa237a9ee7af0482d96829498d7e9ceb972a41073bea0199263c9b1ea808d12b475d32844b091cccc63f6550aadcdd0aa1536849b0c6ef1d676601636b9c62d9cabe1f1e275cf3bfe68b47c62b0cc0a933b82de056233dadcef6dfb2e7ddcfb55719c577b6f793eb470af4f9cb63c82518174704c82a1bdb401888d0643a7c675a945574ed3109c548c4e783f5eddcb0a9ff56c3a70917a43b2ca4182c2e5b0120c5b0627a3c92f3b8f36905ee0ae3bbcb11ddb461b51536ae197a8e16f7ed079e7cbaf772c9d2074ae5c02bf134bb653aa6490fa223989774e70a886dfbd573f2c1d28d3f2ffbbda4a4eb4dbc');
    const n1 = BigInt('0x79e0040b8c80e4e92810368f4395eef926f94def5354e624ef05882655c49e635d4209db61f987b1279999f6e61047222563caffb339d385433c0ffb8ff9c432a2fd7e6b2e0cc43b851068e40a81f536f67a19667abfb4ad0e8ef2b4e4f480a4005b74c169b311e9e095982c9ee3c613e5173613cc3d8b04ca6cb8728764f949d7c2f96bc76d977e7c3277e1b4109ea9e105f6f59a30a8bfc01018fda357f1a0d1b0a05fb68c031dd5f07ff0f6b3128f00cc55cb274e6998bbe9e8552a21fbc9fe51ca2a37c158b01c3aefed66c44f03bde450d04c55ce8cb5e0e9866bbcdc9677372389fe3bf511b8a4f13f8485a30fbe372ffe97477bb7a71a22b0367827d8054fa32b3246647eeb15bf4a860d7cf3d0c091cb8b53d6010c8e67c5d5eaf13291c253e8b1f5f59dd4c09055350b557b95be588c56543bbb3881714efc3fffbd07d65fe1af32b7ccb708e6e15e1c3db12fde80c08967c45e65db2c3dd337db4e0655317d2e484560bde21e47022bd31054d3e85483dfef91323e844f4928559f977d02f4fadcd888e46436fb0c7235466c0dba1361b5725d477e5737f5e9f057c32bb2b849b9f663a19915703500a67d010619de1844d5b4140800d5b423f3b00f1ec22e4b0e50d354cbda714a1e44783010636bb5bd880a3508022024050d8861b74cd206a739ab165a234fa6a6ed917d8f21cab11ea43e1a9bd017b3c683b4');
    const res2 = modPowNative(base1, exponent1, n1);
    const res2Ref = parseBigInteger(base1.toString(16)).modPow(parseBigInteger(exponent1.toString(16)), parseBigInteger(n1.toString(16)));
    expect(res2.toString()).toBe(res2Ref.toString());
  });
});
