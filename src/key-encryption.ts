import secp256k1 from 'secp256k1';
import crypto from 'crypto';

export class KeyEncryption {
	public static ALGORITHM = 'aes-256-gcm';
	// Legacy unauthenticated algorithm. New encryptions always use GCM; this is
	// kept only so decrypt() can still read payloads produced by versions < 1.3.
	public static LEGACY_ALGORITHM = 'aes-256-cbc';
	// 96-bit nonce, recommended for GCM. The encryption key is derived from a
	// *static* ECDH shared secret, so it is reused across every encrypt() call
	// for a given (sender, receiver) pair. GCM security relies on never reusing
	// a (key, nonce) pair: with random 96-bit nonces the birthday bound makes a
	// collision negligible only up to ~2^32 messages under one key. That is far
	// beyond this helper's intended use (encrypting a handful of key shares), but
	// do NOT reuse this class to encrypt high volumes of messages under one key
	// without switching to a counter-based nonce or per-message key derivation.
	private static IV_LENGTH = 12;
	private _encoderPrivateKey: Buffer;
	private _receiverPublicKey: Buffer;
	private _encryptionKey: Buffer;

	constructor(encoderPrivateKey: Buffer, receiverPublicKey: Buffer) {
		this._encoderPrivateKey = encoderPrivateKey;
		this._receiverPublicKey = receiverPublicKey;

		const sharedSecret = secp256k1.ecdh(this._receiverPublicKey, this._encoderPrivateKey, { hashfn: this.hashfn }, Buffer.alloc(33));
		this._encryptionKey = crypto.createHash('sha256').update(sharedSecret).digest();
	}

	hashfn (x, y) {
		const pubKey = new Uint8Array(33)
		pubKey[0] = (y[31] & 1) === 0 ? 0x02 : 0x03
		pubKey.set(x, 1)
		return pubKey
	}

  encrypt(textToEncrypt: string | Buffer, iv = crypto.randomBytes(KeyEncryption.IV_LENGTH)) {
    const cipher = crypto.createCipheriv(KeyEncryption.ALGORITHM, this._encryptionKey, iv) as crypto.CipherGCM;
    const encrypted = Buffer.concat([cipher.update(Buffer.from(textToEncrypt)), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return `${encrypted.toString('hex')}:${iv.toString('hex')}:${authTag.toString('hex')}`;
  }

	decrypt(encryptedPayload: string) {
		const parts = encryptedPayload.split(':');
		if (parts.length === 3) {
			return this.decryptGcm(parts[0], parts[1], parts[2]);
		}
		if (parts.length === 2) {
			// Legacy CBC payload from versions < 1.3. Decrypt for read-back only;
			// encrypt() always emits the authenticated GCM format.
			return this.decryptCbcLegacy(parts[0], parts[1]);
		}
		throw new Error('Invalid encrypted payload: expected "ciphertext:iv:authTag" (GCM) or "ciphertext:iv" (legacy CBC)');
	}

	private decryptGcm(cypherText: string, ivHex: string, authTagHex: string) {
		if (!cypherText || !ivHex || !authTagHex) {
			throw new Error('Invalid encrypted payload: empty field');
		}
		const iv = Buffer.from(ivHex, 'hex');
		const encryptedData = Buffer.from(cypherText, 'hex');
		const decipher = crypto.createDecipheriv(KeyEncryption.ALGORITHM, this._encryptionKey, iv) as crypto.DecipherGCM;
		// Authenticates the ciphertext; final() throws if it has been tampered with.
		decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

		const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
		return decrypted.toString();
	}

	private decryptCbcLegacy(cypherText: string, ivHex: string) {
		if (!cypherText || !ivHex) {
			throw new Error('Invalid encrypted payload: empty field');
		}
		const iv = Buffer.from(ivHex, 'hex');
		const encryptedData = Buffer.from(cypherText, 'hex');
		const decipher = crypto.createDecipheriv(KeyEncryption.LEGACY_ALGORITHM, this._encryptionKey, iv);

		const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
		return decrypted.toString();
	}
}