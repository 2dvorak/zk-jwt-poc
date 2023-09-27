pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
// MIT license
include "./base64.circom";

// MIT license
// reference: https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/helpers/utils.circom
template CalculateTotal(n) {
    signal input nums[n];
    signal output sum;

    signal sums[n];
    sums[0] <== nums[0];

    for (var i=1; i < n; i++) {
        sums[i] <== sums[i - 1] + nums[i];
    }

    sum <== sums[n - 1];
}

// No license..
// reference: https://github.com/TheFrozenFire/snark-jwt-verify/blob/master/circuits/slice.circom
template ArraySlice(n, m) {
    signal input in[n];   // Input array
    signal input offset;  // Offset for the slice
    signal output out[m]; // Output array slice

    // Validate the offset to ensure it's within bounds
    //assert(offset >= 0 && offset + m <= n, "Offset is out of bounds");

    component mux[m];
    component eq[n][m];
    signal check[n][m];
    // Extract the output slice from the input array
    for (var i = 0; i < m; i++) {
        mux[i] = CalculateTotal(n);
        for (var j = 0; j < n; j++) {
            eq[j][i] = IsEqual();
            eq[j][i].in[0] <== j;
            eq[j][i].in[1] <== offset + i;

            mux[i].nums[j] <== eq[j][i].out * in[j];
        }
        out[i] <== mux[i].sum;
    }
}

/*
Takes a base64url encoded JWT as byte sequence and calculates a SHA256 hash,
    as well as extracting public claims from the JWT payload.

    Construction Parameters:
    - jwtLen:               Length of JWT input (header + '.' + payload), assuming byte array.
    - payOffset	            Offset of the payload in base64 decoded JWT, assuming byte array.
    - subLen:               Length of JWT subject claim.
    - issLen:               Length of JWT issuer claim.
    - nonceLen:             Length of JWT nonce claim.
    - audLen:               Length of JWT audience claim.

    Inputs:
    - jwt[jwtLen*8]:        JWT byte sequence input, base64 encoded and 1 bit each.
    - subOffset:            Offset of subject claim in the base64 decoded JWT string.
    - issOffset:            Offset of issuer claim in the base64 decoded JWT string.
    - nonceOffset:          Offset of nonce claim in the base64 decoded JWT string.
    - audOffset:            Offset of audience claim in the base64 decoded JWT string.
    - iatOffset:            Offset of iat(issued at) claim in the base64 decoded JWT string.
    - expOffset:            Offset of exp(expires at) claim in the base64 decoded JWT string.

    Outputs:
    - hash[2]:              SHA256 hash of header+'.'+payload, 128 bits each
                            (one signal cannot store 256 bits because Circom uses a 255 bit curve; the 256 bit hash can have different value after modulo)
    - hSub:                 uint256 Poseidon hash of subject claim
    - iss[issLen]:          issuer claim, byte sequence
    - nonce[nonceLen]:      nonce claim, byte sequence
    - aud[audLen]:          audience claim, byte sequence
    - iat[iatLen]:          issued at claim, byte sequence
    - exp[expLen]:          expired at claim, byte sequence
*/
template ZKVerifyJWT(jwtLen, payOffset, subLen, issLen, nonceLen, audLen) {
    // 76 + 1 + 218 bytes = 295
    signal input jwt[jwtLen*8];

    // we can make these constant, as the payload length is likely fixed (in fact, it should be fixed)
    var base64OutputLen = 3*(jwtLen - payOffset)\4; // 163
    var base64InputLen = 4*((base64OutputLen+2)\3); // 220

    signal output hash[2];
    //signal output hSub[256];
    signal output hSub1;

    // NOTE: Instead, we can get masked input, then compare jwt vs. masked except for the masking

    // can we trust these offsets? what if user generates a JWT like {aud: "https://account.google.com" } or {nonce: "https://account.google.com0xdeadbeef.."}?
    // -> can be detected/limited by fixed lengths
    signal input subOffset;
    signal input issOffset;
    signal input nonceOffset;
    signal input audOffset;
    signal input iatOffset;
    signal input expOffset;

    signal output iss[issLen];
    signal output nonce[nonceLen];
    signal output aud[audLen];
    signal output iat[10];
    signal output exp[10];

    // asserts for input?
    // length
    // header - alg=RS256, typ=JWT

    // First, get SHA256 hash of JWT
    component sha256 = Sha256(jwtLen*8);
    sha256.in <== jwt;
    //hash <== sha256.out;
    component hashChunk1= Bits2Num(128);
    component hashChunk2= Bits2Num(128);
    for (var i = 0; i < 128; i++) {
        hashChunk1.in[127 - i] <== sha256.out[i];
        hashChunk2.in[127 - i] <== sha256.out[128 + i];
    }
    hash[0] <== hashChunk1.out;
    hash[1] <== hashChunk2.out;

    // Then, base64 decode
    component base64 = Base64Decode(base64OutputLen);
    component bit2num[jwtLen - payOffset];
    for (var i = 0; i < jwtLen - payOffset; i++) {
        bit2num[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            // Little endian?
            //bit2num[i].in[j] <== jwt[(payOffset + i) * 8 + j];
            bit2num[i].in[8-j-1] <== jwt[(payOffset + i) * 8 + j];
        }
        base64.in[i] <== bit2num[i].out;
    }
    // pad zero
    for (var i = jwtLen - payOffset; i < base64InputLen; i++) {
        base64.in[i] <== 0;
    }

    signal decoded[base64OutputLen];
    for (var i = 0; i < base64OutputLen; i++) {
        decoded[i] <== base64.out[i];
    }

    component issSlice = ArraySlice(base64OutputLen, issLen);
    issSlice.in <== decoded;
    issSlice.offset <== issOffset;
    iss <== issSlice.out;

    component nonceSlice = ArraySlice(base64OutputLen, nonceLen);
    nonceSlice.in <== decoded;
    nonceSlice.offset <== nonceOffset;
    nonce <== nonceSlice.out;

    component audSlice = ArraySlice(base64OutputLen, audLen);
    audSlice.in <== decoded;
    audSlice.offset <== audOffset;
    aud <== audSlice.out;

    component iatSlice = ArraySlice(base64OutputLen, 10);
    iatSlice.in <== decoded;
    iatSlice.offset <== iatOffset;
    iat <== iatSlice.out;

    component expSlice = ArraySlice(base64OutputLen, 10);
    expSlice.in <== decoded;
    expSlice.offset <== expOffset;
    exp <== expSlice.out;

    signal sub[subLen];
    component subSlice = ArraySlice(base64OutputLen, subLen);
    subSlice.in <== decoded;
    subSlice.offset <== subOffset;
    sub <== subSlice.out;

    component poseidon = Poseidon(subLen);
    for (var i = 0; i < subLen; i++) {
        poseidon.inputs[i] <== sub[i];
    }

    hSub1 <== poseidon.out;
}

component main = ZKVerifyJWT(295, 77, 16, 34, 8, 32);
