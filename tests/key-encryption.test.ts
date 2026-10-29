// KeyEncryption is ceremony tooling, not part of the runtime entry point (SIG-6/SIG-7).
import crypto from "crypto";
import secp256k1 from "secp256k1";
import { KeyEncryption } from "../src/key-encryption";

function keypair() {
  let priv: Buffer;
  do {
    priv = crypto.randomBytes(32);
  } while (!secp256k1.privateKeyVerify(priv));
  return { priv, pub: Buffer.from(secp256k1.publicKeyCreate(priv, false)) };
}

describe("KeyEncryption", () => {
  const encoder = keypair();
  const receiver = keypair();
  let encryptedString: string;

  it("is not exported from the runtime index", () => {
    expect((require("../src") as any).KeyEncryption).toBeUndefined();
  });

  it("should encrypt with the receiver public key and encoder private key", () => {
    const keyEncryption = new KeyEncryption(encoder.priv, receiver.pub);
    encryptedString = keyEncryption.encrypt("Hello, world!");
    expect(encryptedString.length).toBeGreaterThan(0);
    expect(encryptedString).not.toBe("Hello, world!");
    expect(encryptedString.split(":").length).toBe(3);
  });

  it("should decrypt with the receiver private key and encoder public key", () => {
    const keyEncryption = new KeyEncryption(receiver.priv, encoder.pub);
    expect(keyEncryption.decrypt(encryptedString)).toBe("Hello, world!");
  });

  it("should reject a tampered ciphertext (authenticated encryption)", () => {
    const keyEncryption = new KeyEncryption(receiver.priv, encoder.pub);
    const [cypherText, iv, authTag] = encryptedString.split(":");
    const tamperedByte = (parseInt(cypherText.slice(0, 2), 16) ^ 0xff)
      .toString(16)
      .padStart(2, "0");
    expect(() =>
      keyEncryption.decrypt(
        `${tamperedByte}${cypherText.slice(2)}:${iv}:${authTag}`
      )
    ).toThrow();
  });

  it("rejects a legacy 2-field AES-256-CBC payload instead of decrypting it unauthenticated", () => {
    const enc = new KeyEncryption(encoder.priv, receiver.pub);
    const symmetricKey = (enc as any)._encryptionKey as Buffer;
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", symmetricKey, iv);
    const ct = Buffer.concat([
      cipher.update(Buffer.from("ff".repeat(32), "hex")),
      cipher.final(),
    ]);
    ct[0] ^= 0x01; // CBC malleability: this used to decrypt "successfully" to altered plaintext
    const dec = new KeyEncryption(receiver.priv, encoder.pub);
    expect(() =>
      dec.decrypt(`${ct.toString("hex")}:${iv.toString("hex")}`)
    ).toThrow(/CBC|legacy|unsupported/i);
    expect((KeyEncryption as any).LEGACY_ALGORITHM).toBeUndefined();
  });

  it("rejects payloads with an unexpected field count", () => {
    const dec = new KeyEncryption(receiver.priv, encoder.pub);
    expect(() => dec.decrypt("aa")).toThrow(/Invalid encrypted payload/);
    expect(() => dec.decrypt("aa:bb:cc:dd")).toThrow(
      /Invalid encrypted payload/
    );
  });
});
