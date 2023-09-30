const path = require("path");
const fs = require("fs");
const chai = require("chai");
const assert = chai.assert;
const snark = require("snarkjs");

const hardhat = require("hardhat");

function arrayChunk(array, chunk_size) {
    return Array(Math.ceil(array.length / chunk_size)).fill().map((_, index) => index * chunk_size).map(begin => array.slice(begin, begin + chunk_size));
}

function buffer2BitArray(b) {
    return [].concat(...Array.from(b.entries()).map(([index, byte]) => byte.toString(2).padStart(8, '0').split('').map(bit => bit == '1' ? 1 : 0) ))
}

function bitArray2Buffer(a) {
    return Buffer.from(arrayChunk(a, 8).map(byte => parseInt(byte.join(''), 2)))
}

function printProgress(progress) {
    process.stdout.clearLine();
    process.stdout.cursorTo(0);
    process.stdout.write(progress);
}

async function jwtProof(){
    // Timestamps to measure performance
    const timestamps = [];
    const timestamps_labels = ["init", "zkey", "wtns", "prove", "verify", "sol", "compile", "deploy", "ZK verify", "(measure) dummy contract", "(measure) RSA verify only"];
    timestamps.push(new Date());

    // Sample JWT
    const jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InBldmpiYS1welhGU0ZDcnRTYlg5SyJ9.eyJpc3MiOiJodHRwczovL2Rldi05aDQ3YWpjOS51cy5hdXRoMC5jb20vIiwic3ViIjoidHdpdHRlcnwzMzc4MzQxMiIsImF1ZCI6IlQxNWU2NDZiNHVoQXJ5eW9qNEdOUm9uNnpzNE1ySEZWIiwiaWF0IjoxNjM5MTczMDI4LCJleHAiOjE2MzkyMDkwMjgsIm5vbmNlIjoiNDQwMTdhODkifQ.Vg2Vv-NJXdCqLy_JF4ecEsU_NgaA3DXbjwPfqr-euuXc-WPeyF00yRDP6_PVCx9p8PAU48fCMfNAKEFemPpY5Trn8paeweFk6uWZWGR42vo6BShryLFGRdce0MfTEBdZVsYnx-PDFz5aRFYxNnZL8sv2DUJ4NQM_8Zmz2EI7sSV7_kHCoXz7UHIOAtN8_otxCRwvrR3xAJ9P-Qp43HhUqM0fiC4RC3YkVKHRARcWC4bdVLBpKa1BBs4cd2wQ_tzv15YHPEyy4ODZGSX_M9cic-95TcpvVSuymw3bGj6_a7EPxcs6BzZGWlBwsh2ltB6FcLsDuAxxCPIG39tZ3Arp6Q";
    const jwtInput = jwt.split('.')[0] + "." + jwt.split('.')[1];
    //let jwtInput = Buffer.from(jwt.split('.').slice(0,2).join('.'));
    //jwtInput = buffer2BitArray(jwtInput);
    const numBits = 248;
    
    const jwtUintLen = Math.floor(jwtInput.length * 8 / numBits);
    let jwtHexArr = [];
    let jwtSlice;
    let jwtHex;
    for (let i = 0; i < jwtUintLen; i++) {
        jwtSlice = jwtInput.slice(i * numBits / 8, (i + 1) * numBits / 8);
        jwtHex = "";
        for (let j = 0; j < jwtSlice.length; j++) {
            jwtHex += jwtSlice.charCodeAt(j).toString(16).padStart(2, '0');
        }
        jwtHexArr[i] = jwtHex;
    }
    jwtSlice = jwtInput.slice(jwtUintLen * numBits / 8);
    jwtHex = "";
    for (let j = 0; j < jwtSlice.length; j++) {
        jwtHex += jwtSlice.charCodeAt(j).toString(16).padStart(2, '0');
    }
    jwtHexArr.push(jwtHex);

    const jwtUint = jwtHexArr.map(hex => BigInt("0x" + hex));

    const inputs = {
        jwt: jwtUint,
    };
    const decodedPayload = atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'));
    const sig = Buffer.from(jwt.split('.')[2], 'base64url');
    const jwtObject = JSON.parse(decodedPayload);

    // Claims to verify
    const claims = ["sub", "iss", "iat", "exp", "nonce", "aud"];
    claims.forEach(claim => {
        const claimPattern = new RegExp(`"${claim}"\\:\\s*`);
        const claimPatternQuote = new RegExp(`"${claim}"\\:\\s*"`);
        const claimOffset = Math.floor(decodedPayload.search(claimPattern));

        const fieldNameLength = Math.floor(decodedPayload.search(claimPatternQuote)) == -1 ? decodedPayload.match(claimPattern)[0].length : decodedPayload.match(claimPattern)[0].length + 1;

        // Add input signals for ZK
        inputs[claim + "Offset"] = claimOffset + fieldNameLength;
    })

    const zkey_final = {type: "mem"};
    const wtns = {type: "mem"};

    timestamps.push(new Date());

    // Generate zkey
    printProgress("Generating zkey... (takes about a minute)");
    await snark.zKey.newZKey(path.join("build", "jwt.r1cs"), "powersOfTau28_hez_final_19.ptau", zkey_final);
    const vKey = await snark.zKey.exportVerificationKey(zkey_final);

    timestamps.push(new Date());

    // Calculate witness
    printProgress("Calculating witness...");
    await snark.wtns.calculate(inputs, path.join("build", "jwt_js", "jwt.wasm"), wtns);

    timestamps.push(new Date());

    // Generate proof
    printProgress("Generating proof...");
    const {proof: proof, publicSignals: publicSignals} = await snark.groth16.prove(zkey_final, wtns);

    timestamps.push(new Date());

    // Check if proof is valid
    printProgress("Verifying proof...");
    let res = await snark.groth16.verify(vKey, publicSignals, proof);
    assert(res == true);

    timestamps.push(new Date());

    // Generate input for solidity ZK verifier
    const proofA = [proof.pi_a[0], proof.pi_a[1]];
    const proofB = [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]];
    const proofC = [proof.pi_c[0], proof.pi_c[1]];

    // Generate groth16 verifier solidity file from groth16 template + zkey
    const templates = {};
    templates.groth16 = fs.readFileSync(path.join("test", "verifier_groth16.sol.ejs"), "utf8");

    const verifierCode = await snark.zKey.exportSolidityVerifier(zkey_final, templates);
    const solidityVerifierFilename = path.join("contracts", "groth16.sol");
    fs.writeFileSync(solidityVerifierFilename, verifierCode, "utf-8");

    timestamps.push(new Date());

    // Compile the groth16 verifier smart contract
    await hardhat.run("compile");

    timestamps.push(new Date());

    // Deploy JWT verifier's dependency contracts (RSA verifier + groth16 verifier)
    printProgress("Deploying contracts...");
    const ZKFactory = await hardhat.ethers.getContractFactory("Groth16Verifier");
    zkContract = await ZKFactory.deploy();

    const RsaVerify = await hardhat.ethers.getContractFactory("RsaVerify");
    rsaContract = await RsaVerify.deploy();

    const VerifierFactory = await hardhat.ethers.getContractFactory("JWT", {
        libraries: {
            RsaVerify: rsaContract.address,
        }
    });

    // Generate inputs for JWT verifier constructor
    const claimNames = ["iss", "nonce", "aud"];
    const claimLengths = [34, 8, 32];
    const claimValues = claimNames.map(name => Buffer.from(jwtObject[name]));
    for (let i = 0; i < claimNames.length; i++) {
        //claimValues.push(Buffer.from(jwtObject[claimNames[i]]));
    }

    // Deploy JWT verifier contract
    verifierContract = await VerifierFactory.deploy(zkContract.address, claimNames, claimValues);

    timestamps.push(new Date());

    // Verify JWT using ZK
    printProgress("Creating contract calls...");
    let result = await verifierContract.verify(sig, proofA, proofB, proofC, publicSignals);

    timestamps.push(new Date());

    // Reference for performance measure
    // Dummy contract call that immediately returns true
    await verifierContract.returnTrue(sig, proofA, proofB, proofC, publicSignals);

    timestamps.push(new Date());

    // Reference for performance measure
    // Only verify RSA signature
    await verifierContract.rsaVerify(sig, proofA, proofB, proofC, publicSignals);
    assert(result);

    timestamps.push(new Date());

    // Print timestamps
    printProgress("Successfully verified JWT!\nSummary:\n");
    for (let i = 0; i < timestamps.length - 1; i++) {
        console.log(timestamps_labels[i] + " time: ", timestamps[i + 1] - timestamps[i]);
    }
    console.log("zkContract size:", zkContract.deployTransaction.data.length /2);

    return result;
}

jwtProof().then(res => {
    console.log("result:", res);
    process.exit(0);
});
