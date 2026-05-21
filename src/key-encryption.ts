import secp256k1 from 'secp256k1';
import crypto from 'crypto';

export class KeyEncryption {
	public static ALGORITHM = 'aes-256-cbc';
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

  encrypt(textToEncrypt: string | Buffer, iv = crypto.randomBytes(16)) {
    let cipher = crypto.createCipheriv(KeyEncryption.ALGORITHM, this._encryptionKey, iv);
    let encrypted = cipher.update(Buffer.from(textToEncrypt));

    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return `${encrypted.toString('hex')}:${iv.toString('hex')}`;
  }

	decrypt(encryptedPayload: string) {
		let [cypherText, decryptionIV] = encryptedPayload.split(':');
		let iv = Buffer.from(decryptionIV.toString(), 'hex');
		let encryptedData = Buffer.from(cypherText, 'hex');
		let decipher = crypto.createDecipheriv(KeyEncryption.ALGORITHM, this._encryptionKey, iv);

		let decrypted = decipher.update(encryptedData);
		decrypted = Buffer.concat([decrypted, decipher.final()]);

		return decrypted.toString();
  }
}