// script/generateKey.ts
import { ThresholdRSAKey } from '../src/threshold-rsa-key';
import fs from 'fs';
import path from 'path';
import { BigInteger } from '../src/utils';

async function generateKeys() {
    // Get configuration from environment variables
    const bits = parseInt(process.env.RSA_BITS || '4096');
    const exponent = parseInt(process.env.RSA_EXPONENT || '65537');
    const threshold = parseInt(process.env.THRESHOLD || '15');
    const numParties = parseInt(process.env.NUM_PARTIES || '21');

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
            fs.mkdirSync(outputDir);
        }

        const result = await thresholdKey.splitShares(threshold, numParties);

        // Save to file
        const outputPath = path.join(outputDir, 'threshold-keys.json');
        fs.writeFileSync(outputPath, JSON.stringify({
            ...result,
            privateKey: thresholdKey.privateKey
        }, (key, value) => {
            if (value instanceof BigInteger) {
                return value.toString(16);
            }
            return value;
        }, 2));

        console.log('\n===== KEY GENERATION COMPLETE =====', new Date().toISOString());
        console.log(`Keys have been saved to: ${outputPath}`);
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