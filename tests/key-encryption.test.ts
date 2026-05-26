import crypto from 'crypto';
import { KeyEncryption } from '../src';

describe('KeyEncryption', () => {
  let encryptedString: string;
  const encoderPrivateKey = Buffer.from('43d299ea3e0904209c5791bf2732ad4fad5c152537936cb5da2fb8ad0fa0acef', 'hex');
  const encoderPublicKey = Buffer.from('04e9e401a57ede70373fa2a7c2e11a76b2de2a5529d88365ddd9c70f642bf0985693a687bce224c387762b32337fdae37e66c384153719fef6f085bd906e28251d', 'hex');
  const receiverPublicKey = Buffer.from('04db1657a95b941845ad3644b1694953cbf8579b38b4d028cf8a82d40daaa3a447e7748c336b47601ffacdf0c430a782862053d5a242426b8e7f213c793cbf0c5d', 'hex');
  const receiverPrivateKey = Buffer.from('5fc532fe28d8c4a0823239cab5f046a6b43db4f4a424ea733ae56e8472801270', 'hex');

  it('should encrypt with the receiver public key and encoder private key', async () => {
    const keyEncryption = new KeyEncryption(encoderPrivateKey, receiverPublicKey);
    encryptedString = keyEncryption.encrypt('Hello, world!');
    expect(encryptedString.length).toBeGreaterThan(0);
    expect(encryptedString).not.toBe('Hello, world!');
    expect(encryptedString.split(':').length).toBe(3);
  });

  it('should decrypt with the receiver private key and encoder public key', async () => {
    const keyEncryption = new KeyEncryption(receiverPrivateKey, encoderPublicKey);
    const decrypted = keyEncryption.decrypt(encryptedString);
    expect(decrypted).toBe('Hello, world!');
  });

  it('should reject a tampered ciphertext (authenticated encryption)', async () => {
    const keyEncryption = new KeyEncryption(receiverPrivateKey, encoderPublicKey);
    const [cypherText, iv, authTag] = encryptedString.split(':');
    // Flip a byte of the ciphertext; GCM authentication must reject it.
    const tamperedByte = (parseInt(cypherText.slice(0, 2), 16) ^ 0xff).toString(16).padStart(2, '0');
    const tampered = `${tamperedByte}${cypherText.slice(2)}:${iv}:${authTag}`;
    expect(() => keyEncryption.decrypt(tampered)).toThrow();
  });

  it('should still decrypt a legacy 2-part (AES-256-CBC) payload from versions < 1.3', async () => {
    // Build a legacy-format payload using the same symmetric key the class derives.
    const encoder = new KeyEncryption(encoderPrivateKey, receiverPublicKey);
    const symmetricKey = (encoder as any)._encryptionKey as Buffer;
    const legacyIv = crypto.randomBytes(16);
    const legacyCipher = crypto.createCipheriv(KeyEncryption.LEGACY_ALGORITHM, symmetricKey, legacyIv);
    const ct = Buffer.concat([legacyCipher.update(Buffer.from('Hello, world!')), legacyCipher.final()]);
    const legacyPayload = `${ct.toString('hex')}:${legacyIv.toString('hex')}`;

    const receiver = new KeyEncryption(receiverPrivateKey, encoderPublicKey);
    expect(receiver.decrypt(legacyPayload)).toBe('Hello, world!');
  });
});