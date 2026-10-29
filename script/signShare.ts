import NodeRSA from 'node-rsa';
const eosjsAccountName = require('eosjs-account-name');
const crypto = require('crypto');
import { RSASignatureShare, ThresholdRSAVerifier, verifyShareConsistency } from '../src';
import { ThresholdRSAShare } from '../src/threshold-rsa-share';

const keys = require('../generatedKeys/threshold-keys.json');

function make_msg(seedHex, dappName, nonce) {
    const seedBuf = Buffer.from(seedHex, 'hex');
    const nameValue = eosjsAccountName.nameToUint64(dappName);

    const nameBuf = Buffer.alloc(8);
    nameBuf.writeBigUInt64LE(BigInt(nameValue));
    const nBuf = Buffer.alloc(8);
    nBuf.writeBigUInt64LE(BigInt(nonce));
    const finalBuf = Buffer.concat([seedBuf, nameBuf, nBuf]);
    const hash = crypto
      .createHash('sha256')
      .update(finalBuf)
      .digest('hex');
    return hash;
  }

async function signShare() {
    // Get configuration from environment variables
    const bits = keys.bits || 4096;
    // const signingUnint64Number = 99999127887126412n;
    // const signingBuffer = Buffer.alloc(8);
    // signingBuffer.writeBigInt64LE(signingUnint64Number);
    // const message = signingBuffer;
    const messageRaw = make_msg('ef8ffadf514a28eb16250db0a0dcc311a941fb1aa87fc906112696523335d8bc', 'diceexample1', 4);
    const message = Buffer.from(messageRaw, 'hex');

    console.log('===== SIGN SHARE CONFIGURATION =====');
    console.log(`Public Key: `, keys.publicKey);

    const allSignaturesShares: RSASignatureShare[] = [];
    for (let i = 0; i < keys.sharedKey.shares.length; i++) {
        console.log(`Signing share ${i + 1}`);
        try {
            // Create ThresholdRSAKey instance
            const shareConfig = {
                bits,
                sharedKey: keys.sharedKey.shares[i],
                publicKey: keys.publicKey,
                verificationKey: keys.sharedKey.v,
                verificationKeyShare: keys.sharedKey.verificationKeys[i],
                vku: keys.sharedKey.vku
            };
            // Boot-time self-check (what an oracle member should run before signing anything)
            verifyShareConsistency(shareConfig, {
                shareIndex: i + 1,
                numParties: keys.numParties,
                threshold: keys.threshold,
                verificationKeys: keys.sharedKey.verificationKeys,
            });
            const thresholdKey = new ThresholdRSAShare(shareConfig);

            const result = await thresholdKey.signMessage(message, { pkcs1: true, proof: true });

            console.log('\n===== SIGN SHARE COMPLETE =====');
            console.log(`Signature: ${result.signatureShare.toString(16)}`);
            console.log(`Proof: `);
            console.log(` - Z: ${result.proof.z.toString(16)}`);
            console.log(` - C: ${result.proof.c.toString(16)}`);

            allSignaturesShares.push({
                signatureShare: result.signatureShare,
                proof: result.proof,
                shareIndex: i + 1,
            });

        } catch (error) {
            console.error('Error generating keys:', error);
            process.exit(1);
        }
    }

    // Collect random 80% of the shares
    const collectedSignaturesShares: RSASignatureShare[] = [];
    for (let i = 0; i < allSignaturesShares.length; i++) {
        if (Math.floor(Math.random() * 100) >= 20) {
            collectedSignaturesShares.push(allSignaturesShares[i]);
        }
    }

    const thresholdVerifier = new ThresholdRSAVerifier({
        threshold: keys.threshold,
        numParties: keys.numParties,
        bits: keys.bits,
        publicKey: keys.publicKey,
        verificationKey: keys.sharedKey.v,
        vku: keys.sharedKey.vku,
        verificationKeys: keys.sharedKey.verificationKeys,
    });
    // Proof-of-correctness check per share (dealer-published v_i looked up by index)
    console.log('Proofs verify: ', thresholdVerifier.verifySharesMessage(message, collectedSignaturesShares));
    const combined = thresholdVerifier.combineSignatureMessage(message, collectedSignaturesShares);
    const signature = combined.signature;
    console.log(`Signature: `, signature);
    console.log(`Used share indices: `, combined.usedShareIndices, ` attempts: `, combined.attempts);

    // Independent check against a standard RSA implementation (public key only)
    // @ts-ignore
    const key = new NodeRSA();
    key.importKey({
      n: Buffer.from(keys.publicKey.n, 'hex'),
      e: parseInt(keys.publicKey.e, 16),
    }, 'components-public');

    const verifyResult = key.verify(message, Buffer.from(signature, 'hex'), 'buffer', 'buffer');
    
    if (!verifyResult) {
        console.log('Signature is not valid standard RSA')
    }

    // const nodeRsaSignature = key.sign(message, 'buffer', 'hex');
    // console.log('nodeRsaSignature: ', nodeRsaSignature.toString('hex'));

    // const nodeRsaSignatureBigInt = parseBigInteger(nodeRsaSignature.toString('hex'));
    // const eBigInt = parseBigInteger(keys.publicKey.e);
    // const nBigInt = parseBigInteger(keys.publicKey.n);
    // const nodeRSASignMessage = nodeRsaSignatureBigInt.modPow(eBigInt, nBigInt);
    // console.log('nodeRSASignMessage: ', nodeRSASignMessage.toString(16));
}

// Run the key generation
signShare();