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

template DecodeToUintArray(numBits, len) {
    signal input in[len];
    signal output out[len*8\numBits + 1];

    component numBit[len];
    component bitNum[len*8\numBits + 1];
    signal bits[len*8];
    for (var i = 0; i < len; i++) {
        numBit[i] = Num2Bits(8);
        numBit[i].in <== in[i];
        for (var j = 0; j < 8; j++) {
            bits[i*8 + j] <== numBit[i].out[7 - j];
        }
    }
    for (var i = 0; i < len*8\numBits; i++) {
        bitNum[i] = Bits2Num(numBits);
        for (var j = 0; j < numBits; j++) {
            bitNum[i].in[numBits - 1 - j] <== bits[i*numBits + j];
        }
        out[i] <== bitNum[i].out;
    }
    bitNum[len*8\numBits] = Bits2Num(len*8%numBits);
    for (var i = 0; i < len*8%numBits; i++) {
        bitNum[len*8\numBits].in[len*8%numBits - 1 - i] <== bits[(len*8\numBits)*numBits + i];
    }
    out[len*8\numBits] <== bitNum[len*8\numBits].out;
}

template DecodeTimestampToUintArray(numBits) {
    signal input in[10];
    signal output out;

    component numBit[10];
    var base=1;
    var res = 0;
    for (var i = 0; i < 10; i++) {
        assert(in[9 - i] >= 0x30 && in[9 - i] <= 0x39);
        var hex = in[9 - i] - 0x30;
        res += hex * base;
        base = base*10;
    }
    out <== res;
}

/*
Takes a base64url encoded JWT as byte sequence and calculates a SHA256 hash,
    as well as extracting public claims from the JWT payload.

    Construction Parameters:
    - numBits                       Number of bits each signal represents, should be multiple of 8.
    - jwtLen:                       Length of JWT input (header + '.' + payload), assuming byte array.
    - payOffset	                    Offset of the payload in base64 decoded JWT, assuming byte array.
    - subLen:                       Length of JWT subject claim.
    - issLen:                       Length of JWT issuer claim.
    - nonceLen:                     Length of JWT nonce claim.
    - audLen:                       Length of JWT audience claim.

    Inputs:
    - jwt[jwtLen*8\numBits]:  JWT byte sequence input, base64 encoded and 1 bit each.
    - subOffset:                    Offset of subject claim in the base64 decoded JWT string.
    - issOffset:                    Offset of issuer claim in the base64 decoded JWT string.
    - nonceOffset:                  Offset of nonce claim in the base64 decoded JWT string.
    - audOffset:                    Offset of audience claim in the base64 decoded JWT string.
    - iatOffset:                    Offset of iat(issued at) claim in the base64 decoded JWT string.
    - expOffset:                    Offset of exp(expires at) claim in the base64 decoded JWT string.

    Outputs:
    - hash[2]:                      SHA256 hash of header+'.'+payload, 128 bits each
                                    (one signal cannot store 256 bits because Circom uses a 255 bit curve; the 256 bit hash can have different value after modulo)
    - hSub:                         uint256 Poseidon hash of subject claim
    - iss[issLen\numBits]:          issuer claim, byte sequence
    - nonce[nonceLen\numBits]:      nonce claim, byte sequence
    - aud[audLen\numBits]:          audience claim, byte sequence
    - iat[iatLen\numBits]:          issued at claim, byte sequence
    - exp[expLen\numBits]:          expired at claim, byte sequence
*/
template ZKVerifyJWT(numBits, jwtLen, payOffset, subLen, issLen, nonceLen, audLen) {
    // 76 + 1 + 218 bytes = 295
    signal input jwt[jwtLen*8\numBits + 1];

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

    signal output iss[issLen*8\numBits + 1];
    signal output nonce[nonceLen*8\numBits + 1];
    signal output aud[audLen*8\numBits + 1];
    signal output iat[1];
    signal output exp[1];

    // asserts for input?
    // length
    // header - alg=RS256, typ=JWT
    assert(numBits % 8 == 0);

    // 1. get bit-array JWT
    component jwt2bit[jwtLen*8\numBits + 1];
    signal jwtBits[jwtLen*8];
    for (var i = 0; i < jwtLen*8\numBits; i++) {
        jwt2bit[i] = Num2Bits(numBits);
        jwt2bit[i].in <== jwt[i];
        for (var j = 0; j < numBits; j++) {
            jwtBits[i*numBits + numBits - 1 - j] <== jwt2bit[i].out[j];
        }
    }
    if (jwtLen*8%numBits > 0) {
        jwt2bit[jwtLen*8\numBits] = Num2Bits(jwtLen*8%numBits);
        jwt2bit[jwtLen*8\numBits].in <== jwt[jwtLen*8\numBits];
        for (var i = 0; i < jwtLen*8%numBits; i++) {
            jwtBits[(jwtLen*8\numBits)*numBits  + jwtLen*8%numBits - 1 - i] <== jwt2bit[jwtLen*8\numBits].out[i];
        }
    }

    // 2. get SHA256 hash of JWT
    component sha256 = Sha256(jwtLen*8);
    sha256.in <== jwtBits;

    component hashChunk1= Bits2Num(128);
    component hashChunk2= Bits2Num(128);
    for (var i = 0; i < 128; i++) {
        hashChunk1.in[127 - i] <== sha256.out[i];
        hashChunk2.in[127 - i] <== sha256.out[128 + i];
    }
    hash[0] <== hashChunk1.out;
    hash[1] <== hashChunk2.out;

    // 3. get byte-array JWT
    signal jwtBytes[jwtLen];
    component jwtBit2Byte[jwtLen];
    for (var i = 0; i < jwtLen; i++) {
        jwtBit2Byte[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            jwtBit2Byte[i].in[j] <== jwtBits[i*8 + j];
        }
        jwtBytes[i] <== jwtBit2Byte[i].out;
    }

    // 4. base64 decode
    component base64 = Base64Decode(base64OutputLen);
    component bit2num[jwtLen - payOffset];
    for (var i = 0; i < jwtLen - payOffset; i++) {
        bit2num[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            // Little endian?
            //bit2num[i].in[j] <== jwt[(payOffset + i) * 8 + j];
            bit2num[i].in[8-j-1] <== jwtBits[(payOffset + i) * 8 + j];
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

    // 5. get byte-array claims
    component issSlice = ArraySlice(base64OutputLen, issLen);
    issSlice.in <== decoded;
    issSlice.offset <== issOffset;
    component nonceSlice = ArraySlice(base64OutputLen, nonceLen);
    nonceSlice.in <== decoded;
    nonceSlice.offset <== nonceOffset;
    component audSlice = ArraySlice(base64OutputLen, audLen);
    audSlice.in <== decoded;
    audSlice.offset <== audOffset;
    component iatSlice = ArraySlice(base64OutputLen, 10);
    iatSlice.in <== decoded;
    iatSlice.offset <== iatOffset;
    component expSlice = ArraySlice(base64OutputLen, 10);
    expSlice.in <== decoded;
    expSlice.offset <== expOffset;

    // 6. get uint-array claims
    component issDecode = DecodeToUintArray(numBits, issLen);
    issDecode.in <== issSlice.out;
    iss <== issDecode.out;

    component nonceDecode = DecodeToUintArray(numBits, nonceLen);
    nonceDecode.in <== nonceSlice.out;
    nonce <== nonceDecode.out;

    component audDecode = DecodeToUintArray(numBits, audLen);
    audDecode.in <== audSlice.out;
    aud <== audDecode.out;

    component iatDecode = DecodeTimestampToUintArray(numBits);
    iatDecode.in <== iatSlice.out;
    iat[0] <== iatDecode.out;

    component expDecode = DecodeTimestampToUintArray(numBits);
    expDecode.in <== expSlice.out;
    exp[0] <== expDecode.out;

    // 7. get subject ID
    signal sub[subLen];
    component subSlice = ArraySlice(base64OutputLen, subLen);
    subSlice.in <== decoded;
    subSlice.offset <== subOffset;
    sub <== subSlice.out;

    // 8. get hash of subject ID
    component poseidon = Poseidon(subLen);
    for (var i = 0; i < subLen; i++) {
        poseidon.inputs[i] <== sub[i];
    }

    hSub1 <== poseidon.out;
}

component main = ZKVerifyJWT(248, 295, 77, 16, 34, 8, 32);
