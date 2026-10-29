// script/generateKey.ts — trusted-dealer key ceremony (sample tooling).
//
// Writes the public key, the dealer parameters (v, u) and ALL party shares to
// generatedKeys/threshold-keys.json. The shares in that file ARE the secret: the
// intended path is to wrap each share to its party with KeyEncryption
// (src/key-encryption.ts: ECDH(secp256k1) + AES-256-GCM), hand the wrapped
// shares out, and destroy this file. See README "Key ceremony".
//
// The unshared private key (p, q, d, …) is NOT written unless the operator passes
// --unsafe-write-private-key. Anyone holding it can sign alone and the threshold
// is decorative (audit finding SIG-3).
import { ThresholdRSAKey } from '../src/threshold-rsa-key';
import fs from 'fs';
import path from 'path';
import { BigInteger } from '../src/utils';

const UNSAFE_FLAG = '--unsafe-write-private-key';

async function generateKeys() {
    // Get configuration from environment variables
    const bits = parseInt(process.env.RSA_BITS || '4096');
    const exponent = parseInt(process.env.RSA_EXPONENT || '65537');
    const threshold = parseInt(process.env.THRESHOLD || '15');
    const numParties = parseInt(process.env.NUM_PARTIES || '21');
    const writePrivateKey = process.argv.includes(UNSAFE_FLAG);

    console.log('===== KEY GENERATION CONFIGURATION =====', new Date().toISOString());
    console.log(`RSA Key Size: ${bits} bits`);
    console.log(`Threshold: ${threshold} of ${numParties}`);

    try {
        // Create ThresholdRSAKey instance
        const thresholdKey = new ThresholdRSAKey({ bits, e: exponent });

        // Generate keys and shares
        await thresholdKey.generateKeyPair();

        // Create output directory if it doesn't exist
        const outputDir = path.join(__dirname, '../generatedKeys');
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { mode: 0o700 });
        }

        const result = await thresholdKey.splitShares(threshold, numParties);

        const output: any = { ...result };
        if (writePrivateKey) {
            console.warn('\n!!! WARNING: ' + UNSAFE_FLAG + ' given — the UNSHARED RSA private key (p, q, d) will be');
            console.warn('!!! written to disk in plaintext. Whoever holds this file can sign alone; the');
            console.warn('!!! threshold protects nothing while it exists. Destroy it after use.\n');
            output.privateKey = thresholdKey.privateKey;
        }

        // Save to file
        const outputPath = path.join(outputDir, 'threshold-keys.json');
        if (fs.existsSync(outputPath)) {
            throw new Error(`${outputPath} already exists — move or destroy the previous ceremony output first`);
        }
        const fd = fs.openSync(outputPath, 'wx', 0o600); // create-only, owner read/write
        fs.writeFileSync(fd, JSON.stringify(output, (key, value) => {
            if (value instanceof BigInteger) {
                return value.toString(16);
            }
            return value;
        }, 2));
        fs.closeSync(fd);
        fs.chmodSync(outputPath, 0o600);

        console.log('\n===== KEY GENERATION COMPLETE =====', new Date().toISOString());
        console.log(`Keys have been saved to: ${outputPath}`);
        console.log(writePrivateKey
            ? '- The file INCLUDES the unshared private key (see warning above).'
            : `- The unshared private key was NOT written (pass ${UNSAFE_FLAG} to force it; not recommended).`);
        console.log('- The file contains every party\'s share in plaintext: wrap each share to its party');
        console.log('  with KeyEncryption, distribute the wrapped shares, then destroy this file.');
        console.log('\nKey Information:');
        console.log(`- Public Key (n): ${result.publicKey.n.toString(16)}`);
        console.log(`- Number of Shares: ${result.sharedKey.shares.length}`);
        console.log(`- Threshold: ${threshold}`);
        console.log(`- Total Parties: ${numParties}`);

    } catch (error) {
        console.error('Error generating keys:', error);
        process.exit(1);
    }
}

// Run the key generation
generateKeys();
