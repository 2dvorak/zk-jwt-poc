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

template MaskedCompare(len, maskLen) {
    signal input in[len];   // Input array
    signal input masked[len];
    signal input offset;  // Offset for the slice
    signal output out; // Output bool

    // Validate the offset to ensure it's within bounds
    //assert(offset >= 0 && offset + m <= n, "Offset is out of bounds");

    component eq[len][len];
    component mux[len];
    signal check[len];
    signal res[len];
    for (var i = 0; i < len; i++) {
        check[i] <== in[i] - masked[i];
    }
    for (var i = 0; i < len; i++) {
        mux[i] = CalculateTotal(len);
        for (var j = 0; j < len; j++) {
            eq[j][i] = IsEqual();
            eq[j][i].in[0] <== j;
            eq[j][i].in[1] <== offset + i;

            mux[i].nums[j] <== (eq[j][i].out - 1) * check[j];
        }
        res[i] <== mux[i].sum;
    }
    signal res2[len];
    component check2[len];
    for (var i = 0; i < len; i++) {
        check2[i] = IsZero();
        check2[i].in <== res[i];
        res2[i] <== check2[i].out;
    }
    signal res3[len];
    component check3[len];
    for (var i=0; i< len; i++) {
        check3[i] = IsEqual();
        check3[i].in[0] <== res2[i];
        check3[i].in[1] <== 1;
        res3[i] <== check3[i].out;
    }
    component add = CalculateTotal(len);
    add.nums <== res3;
    out <== add.sum;
}

template Uints2Bits(bitLen, numBits) {
    signal input uints[bitLen\numBits + 1];
    component num2bit[bitLen\numBits + 1];
    signal output bits[bitLen];
    for (var i = 0; i < bitLen\numBits; i++) {
        num2bit[i] = Num2Bits(numBits);
        num2bit[i].in <== uints[i];
        for (var j = 0; j < numBits; j++) {
            bits[i*numBits + numBits - 1 - j] <== num2bit[i].out[j];
        }
    }
    if (bitLen%numBits > 0) {
        num2bit[bitLen\numBits] = Num2Bits(bitLen%numBits);
        num2bit[bitLen\numBits].in <== uints[bitLen\numBits];
        for (var i = 0; i < bitLen%numBits; i++) {
            bits[(bitLen\numBits)*numBits  + bitLen%numBits - 1 - i] <== num2bit[bitLen\numBits].out[i];
        }
    }

}

template Bits2Bytes(len) {
    signal input bits[len];
    signal output bytes[len\8];

    assert(len % 8 == 0);

    component bit2Byte[len\8];
    for (var i = 0; i < len\8; i++) {
        bit2Byte[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            bit2Byte[i].in[j] <== bits[i*8 + j];
        }
        bytes[i] <== bit2Byte[i].out;
    }
}

/*
Takes a base64url encoded JWT as byte sequence and calculates a SHA256 hash,
    as well as extracting public claims from the JWT payload.

    Construction Parameters:
    - numBits                       Number of bits each signal represents, should be multiple of 8.
    - jwtLen:                       Length of JWT input (header + '.' + payload), assuming byte array.
    - payOffset	                    Offset of the payload in base64 decoded JWT, assuming byte array.
    - subLen:                       Length of JWT subject claim.

    Inputs:
    - jwt[jwtLen*8\numBits+1]:      JWT byte sequence input, base64 encoded and `numBits` bit each.
    - masked[base64OutputLen]:      JWT byte sequence input, plain text and `numBits` bit each
    - subOffset:                    Offset of subject claim in the base64 decoded JWT string.

    Outputs:
    - hash[2]:                      SHA256 hash of header+'.'+payload, 128 bits each
                                    (one signal cannot store 256 bits because Circom uses a 255 bit curve; the 256 bit hash can have different value after modulo)
    - hSub:                         uint256 Poseidon hash of subject claim
*/
template ZKVerifyJWT(numBits, jwtLen, payOffset, subLen) {
    // 76 + 1 + 218 bytes = 295
    signal input jwt[jwtLen*8\numBits + 1];

    // we can make these constant, as the payload length is likely fixed (in fact, it should be fixed)
    var base64OutputLen = 3*(jwtLen - payOffset)\4; // 163
    var base64InputLen = 4*((base64OutputLen+2)\3); // 220

    signal input masked[base64OutputLen*8\numBits + 1];

    signal output hash[2];
    //signal output hSub[256];
    signal output hSub1;

    // NOTE: Instead, we can get masked input, then compare jwt vs. masked except for the masking

    // can we trust these offsets? what if user generates a JWT like {aud: "https://account.google.com" } or {nonce: "https://account.google.com0xdeadbeef.."}?
    // -> can be detected/limited by fixed lengths
    signal input subOffset;
    //signal input issOffset;
    //signal input nonceOffset;
    //signal input audOffset;
    //signal input iatOffset;
    //signal input expOffset;

    //signal output iss[issLen*8\numBits + 1];
    //signal output nonce[nonceLen*8\numBits + 1];
    //signal output aud[audLen*8\numBits + 1];
    //signal output iat[1];
    //signal output exp[1];

    // asserts for input?
    // length
    // header - alg=RS256, typ=JWT
    assert(numBits % 8 == 0);

    // 1. get bit-array & byte-array JWT
    component jwt2bits = Uints2Bits(jwtLen*8, numBits);
    jwt2bits.uints <== jwt;
    component jwtBits2Bytes = Bits2Bytes(jwtLen*8);
    jwtBits2Bytes.bits <== jwt2bits.bits;

    // 2. get SHA256 hash of JWT
    component sha256 = Sha256(jwtLen*8);
    sha256.in <== jwt2bits.bits;

    component hashChunk1= Bits2Num(128);
    component hashChunk2= Bits2Num(128);
    for (var i = 0; i < 128; i++) {
        hashChunk1.in[127 - i] <== sha256.out[i];
        hashChunk2.in[127 - i] <== sha256.out[128 + i];
    }
    hash[0] <== hashChunk1.out;
    hash[1] <== hashChunk2.out;

    // 3. base64 decode
    component base64 = Base64Decode(base64OutputLen);
    for (var i = 0; i < jwtLen - payOffset; i++) {
        base64.in[i] <== jwtBits2Bytes.bytes[payOffset + i];
    }
    // pad zero
    for (var i = jwtLen - payOffset; i < base64InputLen; i++) {
        base64.in[i] <== 0;
    }
    signal decoded[base64OutputLen];
    for (var i = 0; i < base64OutputLen; i++) {
        decoded[i] <== base64.out[i];
    }

    // 4. get byte-array masked JWT
    component masked2bits = Uints2Bits(base64OutputLen*8, numBits);
    masked2bits.uints <== masked;
    component masked2bytes = Bits2Bytes(base64OutputLen*8);
    masked2bytes.bits <== masked2bits.bits;

    // 5. compare decoded JWT vs masked JWT
    component compare = MaskedCompare(base64OutputLen, subLen);
    compare.in <== decoded;
    compare.masked <== masked2bytes.bytes;
    compare.offset <== subOffset;
    assert(compare.out == 0);

    // 6. get subject ID
    signal sub[subLen];
    component subSlice = ArraySlice(base64OutputLen, subLen);
    subSlice.in <== decoded;
    subSlice.offset <== subOffset;
    sub <== subSlice.out;

    // 7. get hash of subject ID
    component poseidon = Poseidon(subLen);
    for (var i = 0; i < subLen; i++) {
        poseidon.inputs[i] <== sub[i];
    }

    hSub1 <== poseidon.out;
}

component main { public [masked] } = ZKVerifyJWT(248, 295, 77, 16);
