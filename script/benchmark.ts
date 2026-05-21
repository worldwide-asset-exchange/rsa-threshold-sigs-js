import crypto from 'crypto';
import { ThresholdRSAShare } from '../src/threshold-rsa-share';

const keys = require('../generatedKeys/threshold-keys.json');

function benchmarkSignMessage() {
    const bits = 4096;
    const iterations = 20;

    console.log('===== BENCHMARK CONFIGURATION =====');
    console.log(`Iterations: ${iterations}`);
    console.log(`Key Size: ${bits} bits`);
    console.log(`Number of Shares: ${keys.sharedKey.shares.length}\n`);

    // Create ThresholdRSAShare instance for first share
    const thresholdKey = new ThresholdRSAShare({
        bits,
        sharedKey: keys.sharedKey.shares[0],
        publicKey: keys.publicKey,
        verificationKey: keys.sharedKey.v,
        verificationKeyShare: keys.sharedKey.verificationKeys[0],
        vku: keys.sharedKey.vku
    });

    // Benchmark with pkcs1=true (default)
    console.log('\n===== BENCHMARKING signMessage (pkcs1=true) =====');
    const startPkcs = Date.now();
    for (let i = 0; i < iterations; i++) {
        const message = Buffer.from('test message for benchmarking' + i);
        thresholdKey.signMessage(message, { pkcs1: true });
    }
    const endPkcs = Date.now();
    const totalTimePkcs = endPkcs - startPkcs;
    const avgTimePkcs = totalTimePkcs / iterations;

    console.log(`Total time: ${totalTimePkcs}ms`);
    console.log(`Average time per signature: ${avgTimePkcs.toFixed(2)}ms`);
    console.log(`Signatures per second: ${(1000 / avgTimePkcs).toFixed(2)}`);

    // Benchmark with pkcs1=false
    console.log('\n===== BENCHMARKING signMessage (pkcs1=false) =====');
    const startNoPkcs = Date.now();
    for (let i = 0; i < iterations; i++) {
        const message = Buffer.from('test message for benchmarking' + i);
        thresholdKey.signMessage(message, { pkcs1: false });
    }
    const endNoPkcs = Date.now();
    const totalTimeNoPkcs = endNoPkcs - startNoPkcs;
    const avgTimeNoPkcs = totalTimeNoPkcs / iterations;

    console.log(`Total time: ${totalTimeNoPkcs}ms`);
    console.log(`Average time per signature: ${avgTimeNoPkcs.toFixed(2)}ms`);
    console.log(`Signatures per second: ${(1000 / avgTimeNoPkcs).toFixed(2)}`);

    // Benchmark with proof generation
    console.log('\n===== BENCHMARKING signMessage (with proof) =====');
    const startProof = Date.now();
    for (let i = 0; i < iterations; i++) {
        const message = Buffer.from('test message for benchmarking' + i);
        thresholdKey.signMessage(message, { pkcs1: true, proof: true });
    }
    const endProof = Date.now();
    const totalTimeProof = endProof - startProof;
    const avgTimeProof = totalTimeProof / iterations;

    console.log(`Total time: ${totalTimeProof}ms`);
    console.log(`Average time per signature: ${avgTimeProof.toFixed(2)}ms`);
    console.log(`Signatures per second: ${(1000 / avgTimeProof).toFixed(2)}`);

    console.log('\n===== BENCHMARK SUMMARY =====');
    console.log(`pkcs1=true:  ${avgTimePkcs.toFixed(2)}ms per signature`);
    console.log(`pkcs1=false: ${avgTimeNoPkcs.toFixed(2)}ms per signature`);
    console.log(`with proof:  ${avgTimeProof.toFixed(2)}ms per signature`);
}

benchmarkSignMessage();
