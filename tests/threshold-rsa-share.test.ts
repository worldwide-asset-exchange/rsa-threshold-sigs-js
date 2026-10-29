import NodeRSA from 'node-rsa';
import { PublicKey, RSASignatureShare, Share, ThresholdRSAKey, ThresholdRSAShare, ThresholdRSAVerifier } from '../src';
import { BigInteger, emsaPkcs1v15encode, jacobiSymbol, parseBigInteger } from '../src/utils';

describe('ThresholdRSAShare ThresholdRSAVerifier', () => {
  let thresholdRSAKey: ThresholdRSAKey;
  let thresholdRSAVerifier: ThresholdRSAVerifier;
  let threshold = 8;
  let numParties = 10;
  let bits = 4096;
  let shares: { publicKey: PublicKey, sharedKey: Share };

  beforeAll(async () => {
    thresholdRSAKey = new ThresholdRSAKey({ bits });
    await thresholdRSAKey.generateKeyPair();
    shares = await thresholdRSAKey.splitShares(threshold, numParties);
    thresholdRSAVerifier = new ThresholdRSAVerifier({
      threshold,
      numParties,
      bits,
      publicKey: shares.publicKey,
      verificationKey: shares.sharedKey.v,
      vku: shares.sharedKey.vku,
      // dealer-published per-party verification keys (required for proof verification since 2.0.0)
      verificationKeys: shares.sharedKey.verificationKeys,
    });
  });

  it('should throw if invalid config', async () => {
    expect(() => new ThresholdRSAKey({ bits: 1023 })).toThrow('Invalid bits: must be between 1024 and 4096');
    expect(() => new ThresholdRSAKey({ bits: 4097 })).toThrow('Invalid bits: must be between 1024 and 4096');
  });

  it('should sign and generate proof', async () => {
    let collectedShares: RSASignatureShare[] = [];
    const message = 'this is message to sign share share';
    let msgBigInt = new BigInteger('da5f53a808910d45b50eea5d4ddf6a90e1951f10b9bb711ad0a75f6f55c7fe9f', 16);
    const encodedPkcs1 = emsaPkcs1v15encode(Buffer.from(msgBigInt.toString(16), 'hex'), bits);
		let msgBigIntToSign = parseBigInteger(encodedPkcs1.toString('hex'));
    if (jacobiSymbol(msgBigIntToSign, thresholdRSAKey.publicKey.n) == -1) {
      msgBigIntToSign = msgBigIntToSign.multiply(shares.sharedKey.vku.modPow(shares.publicKey.e, thresholdRSAKey.publicKey.n)).mod(thresholdRSAKey.publicKey.n);
    }
    for (let i = 0; i < numParties; i++) {
      // sign message with share `shareIndex`
      const shareIndex = i;
      const shareInstance = new ThresholdRSAShare({
        bits,
        publicKey: shares.publicKey,
        sharedKey: shares.sharedKey.shares[shareIndex],
        vku: shares.sharedKey.vku,
        verificationKey: shares.sharedKey.v,
        verificationKeyShare: shares.sharedKey.verificationKeys[shareIndex]
      });
      const signResult = shareInstance.signMessage(message, { proof: true });
      expect(signResult.signatureShare).toBeDefined();
      expect(signResult.proof).toBeDefined();
      expect(signResult.msgBigInt.equals(msgBigInt)).toBe(true);
      expect(signResult.msgBigIntToSign.equals(msgBigIntToSign)).toBe(true);

      expect(signResult.signatureShare.compareTo(thresholdRSAKey.publicKey.n)).toBeLessThan(0);
      // message is hashed to 256 bits
      expect(signResult.msgBigInt.bitLength()).toBeLessThanOrEqual(256);

      const signHashResult = shareInstance.signHash(msgBigInt);
      expect(signHashResult.signatureShare.equals(signResult.signatureShare)).toBe(true);

      // sha256 hash of transcript is 256 bits
      expect(signResult.proof.c.bitLength()).toBeLessThanOrEqual(256);
      expect(signResult.proof.z.compareTo(shares.sharedKey.shares[shareIndex].multiply(signResult.proof.c))).toBeGreaterThan(0);

      const signatureShare = {
        signatureShare: signResult.signatureShare,
        proof: signResult.proof,
        sharedVerificationKey: shares.sharedKey.verificationKeys[shareIndex],
        shareIndex: shareIndex + 1,
      }

      // verify signature shares and proofs
      const verifyResult = thresholdRSAVerifier.verifySharesHash(msgBigInt, [signatureShare]);
      expect(verifyResult).toBe(true);
      // Collect a random subset of shares, but always keep at least `threshold`
      // so the combine step below is deterministic and never under-supplied.
      if (collectedShares.length < threshold || Math.random()*1000 >= 150) {
        collectedShares.push(signatureShare);
      }

      const verifyResultMessage = thresholdRSAVerifier.verifySharesMessage(message, [signatureShare]);
      expect(verifyResultMessage).toBe(true);
    }

    const signature = thresholdRSAVerifier.verifySignatureHash(msgBigInt, collectedShares);
    expect(signature.length).toBe(1024);
    expect(parseBigInteger(signature).compareTo(thresholdRSAKey.publicKey.n)).toBeLessThan(0);

    const signatureMessage = thresholdRSAVerifier.verifySignatureMessage(message, collectedShares);
    expect(signatureMessage.length).toBe(1024);
    expect(parseBigInteger(signatureMessage).compareTo(thresholdRSAKey.publicKey.n)).toBeLessThan(0);

    // Make sure combine signature are compliance with standard by using exsiting library to verify it
    // @ts-ignore
    const key = new NodeRSA();
    key.importKey({
      n: Buffer.from(thresholdRSAKey.publicKey.n.toString(16), 'hex'),
      e: 65537,
    }, 'components-public');

    const verifyResult = key.verify(Buffer.from(message, 'utf8'), Buffer.from(signature, 'hex'), 'buffer', 'buffer');
    expect(verifyResult).toBe(true);
  });

  it('should disable generate proof', async () => {
    const message = 'test message for diable proof';
  
    const shareIndex = 0; // Same index for both shares
    const shareInstance = new ThresholdRSAShare({
      bits,
      publicKey: shares.publicKey,
      sharedKey: shares.sharedKey.shares[shareIndex],
      vku: shares.sharedKey.vku,
      verificationKey: shares.sharedKey.v,
      verificationKeyShare: shares.sharedKey.verificationKeys[shareIndex]
    });
    
    const signResult = shareInstance.signMessage(message);

    expect(signResult.signatureShare).toBeDefined();
    expect(signResult.proof).toBeUndefined();
    expect(signResult.signatureShare.compareTo(thresholdRSAKey.publicKey.n)).toBeLessThan(0);
  });

  it('should reject duplicate share indices', async () => {
    let collectedShares: RSASignatureShare[] = [];
    const message = 'test message for duplicate validation';
    let msgBigInt = new BigInteger('da5f53a808910d45b50eea5d4ddf6a90e1951f10b9bb711ad0a75f6f55c7fe9f', 16);
  
    // Create shares with the same shareIndex
    for (let i = 0; i < 8; i++) {
      const shareIndex = 0; // Same index for both shares
      const shareInstance = new ThresholdRSAShare({
        bits,
        publicKey: shares.publicKey,
        sharedKey: shares.sharedKey.shares[shareIndex],
        vku: shares.sharedKey.vku,
        verificationKey: shares.sharedKey.v,
        verificationKeyShare: shares.sharedKey.verificationKeys[shareIndex]
      });
      
      const signResult = shareInstance.signMessage(message);
      const signatureShare = {
        signatureShare: signResult.signatureShare,
        proof: signResult.proof,
        sharedVerificationKey: shares.sharedKey.verificationKeys[shareIndex],
        shareIndex: shareIndex + 1, // Same shareIndex for both
      };
      
      collectedShares.push(signatureShare);
    }
  
    // Attempt to verify signature with duplicate shares should throw error
    expect(() => {
      thresholdRSAVerifier.verifySignatureHash(msgBigInt, collectedShares);
    }).toThrow('Duplicate share indices detected');
  });
  
  it('should reject duplicate share indices in different positions', async () => {
    let collectedShares: RSASignatureShare[] = [];
    const message = 'test message for duplicate validation';
    let msgBigInt = new BigInteger('da5f53a808910d45b50eea5d4ddf6a90e1951f10b9bb711ad0a75f6f55c7fe9f', 16);
  
    // Create shares with indices 1, 2, 1 (duplicate 1)
    const shareIndices = [0, 1, 0, 2, 3, 4, 5, 6, 7]; // Using 0-based for array access, but will use 1-based for shareIndex
    
    for (let i = 0; i < shareIndices.length; i++) {
      const arrayIndex = shareIndices[i];
      const shareInstance = new ThresholdRSAShare({
        bits,
        publicKey: shares.publicKey,
        sharedKey: shares.sharedKey.shares[arrayIndex],
        vku: shares.sharedKey.vku,
        verificationKey: shares.sharedKey.v,
        verificationKeyShare: shares.sharedKey.verificationKeys[arrayIndex]
      });
      
      const signResult = shareInstance.signMessage(message);
      const signatureShare = {
        signatureShare: signResult.signatureShare,
        proof: signResult.proof,
        sharedVerificationKey: shares.sharedKey.verificationKeys[arrayIndex],
        shareIndex: arrayIndex + 1, // Convert to 1-based indexing
      };
      
      collectedShares.push(signatureShare);
    }
  
    // Should detect duplicate shareIndex 1
    expect(() => {
      thresholdRSAVerifier.verifySignatureHash(msgBigInt, collectedShares);
    }).toThrow('Duplicate share indices detected');
  });

  it('should reject an out-of-range share index', async () => {
    const message = 'test message for index range validation';
    let msgBigInt = new BigInteger('da5f53a808910d45b50eea5d4ddf6a90e1951f10b9bb711ad0a75f6f55c7fe9f', 16);

    // Build `threshold` distinct shares, but force the first one's shareIndex to
    // 0, which is outside the valid [1, numParties] range.
    const collectedShares: RSASignatureShare[] = [];
    for (let i = 0; i < threshold; i++) {
      const shareInstance = new ThresholdRSAShare({
        bits,
        publicKey: shares.publicKey,
        sharedKey: shares.sharedKey.shares[i],
        vku: shares.sharedKey.vku,
        verificationKey: shares.sharedKey.v,
        verificationKeyShare: shares.sharedKey.verificationKeys[i],
      });
      const signResult = shareInstance.signMessage(message);
      collectedShares.push({
        signatureShare: signResult.signatureShare,
        proof: signResult.proof,
        sharedVerificationKey: shares.sharedKey.verificationKeys[i],
        shareIndex: i === 0 ? 0 : i + 1, // index 0 is out of range
      });
    }

    expect(() => {
      thresholdRSAVerifier.verifySignatureHash(msgBigInt, collectedShares);
    }).toThrow('Invalid share index 0');
  });

  it('should reject an empty share set in verifySharesHash (no vacuous true)', async () => {
    const msgBigInt = new BigInteger('da5f53a808910d45b50eea5d4ddf6a90e1951f10b9bb711ad0a75f6f55c7fe9f', 16);
    expect(thresholdRSAVerifier.verifySharesHash(msgBigInt, [])).toBe(false);
  });
});
