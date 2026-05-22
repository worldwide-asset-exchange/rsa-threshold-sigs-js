import secp256k1 from 'secp256k1';
import crypto from 'crypto';

export class KeyEncryption {
	public static ALGORITHM = 'aes-256-gcm';
	private static IV_LENGTH = 12; // 96-bit nonce, recommended for GCM
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
		const [cypherText, decryptionIV, authTagHex] = encryptedPayload.split(':');
		if (!cypherText || !decryptionIV || !authTagHex) {
			throw new Error('Invalid encrypted payload: expected "ciphertext:iv:authTag"');
		}
		const iv = Buffer.from(decryptionIV, 'hex');
		const encryptedData = Buffer.from(cypherText, 'hex');
		const decipher = crypto.createDecipheriv(KeyEncryption.ALGORITHM, this._encryptionKey, iv) as crypto.DecipherGCM;
		// Authenticates the ciphertext; final() throws if it has been tampered with.
		decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

		const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

		return decrypted.toString();
  }
}