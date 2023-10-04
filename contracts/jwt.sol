// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "./izkverify.sol";
import "./rsa.sol";
import "hardhat/console.sol";
import "./JsmnSolLib.sol";

contract JWT {

    uint public constant NUMBER_OF_CLAIMS = 3;
    string[] public CLAIM_NAMES = ["iss", "nonce", "aud"];
    uint public constant NUM_BITS = 31;
    uint public constant MASKED_JWT_LEN = 163;
    uint public constant PUB_SIGNAL_CLAIMS_LENGTH = MASKED_JWT_LEN / NUM_BITS + 1;
    uint public constant PUB_SIGNAL_JWT_HASH_LENGTH = 2;
    uint public constant PUB_SIGNAL_SUB_HASH_LENGTH = 1;
    uint public constant PUB_SIGNAL_LENGTH = PUB_SIGNAL_JWT_HASH_LENGTH + PUB_SIGNAL_SUB_HASH_LENGTH + PUB_SIGNAL_CLAIMS_LENGTH;
    address public zkVerify;
    mapping (string => bytes) public claims;
    mapping (string => ClaimInfo) public claimInfo;

    struct ClaimInfo {
        uint len;
    }

    constructor(address _zkVerify, string[] memory _claimNames, bytes[] memory _claimValues) {
        zkVerify = _zkVerify;
        require(_claimNames.length == NUMBER_OF_CLAIMS, "number of claim names does not match");
        require(_claimValues.length == NUMBER_OF_CLAIMS, "number of claim values does not match");

        uint claimsLen = 0;
        for (uint i = 0; i < NUMBER_OF_CLAIMS; i++) {
            claims[_claimNames[i]] = _claimValues[i];
            claimInfo[_claimNames[i]] = ClaimInfo(_claimValues[i].length);
            claimsLen += _claimValues[i].length;
        }
    }

    // Dummy function to measure performance of ZK proof verification
    function returnTrue(bytes calldata, uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[PUB_SIGNAL_LENGTH] memory) public pure returns (bool) {
        return true;
    }

    // Dummy function to measure performance of ZK proof verification
    function rsaVerify(bytes calldata sig, uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[PUB_SIGNAL_LENGTH] memory _pubSignals) public view returns (bool) {
        bytes32 hash = extractHashFromPubSignal(_pubSignals);

        bytes memory n =    hex"b11e042ac1890495b395065fc7e033e488328563a8e1d7846373c069d13d9234"
                            hex"1ccb18f9cdc4d269ee2b07a622398b44cea8dc7be757869b9bc634bfa25af49f"
                            hex"4a6e0913749bbbb91e18a6d36f7f7f580dd874287dc091b4963873a56be71929"
                            hex"ae6492c64d76eed60a2755fef3abf324b3d1da9dd5524ce74e0b2410fe5bc6f1"
                            hex"d5ca3f35e0d40b85d32614024ec2ef54baeda8184e1307722266048263c80076"
                            hex"de187c25ea15e2c158f3bddc95703dd5384cddf044c4f0133fdbcb9655dbd8e0"
                            hex"f0e9f6581584b7a44be4164483f331cba396fd833f72c2afafc8ab24c4eff2ce"
                            hex"15f868b33b6154402754450c9f087c83f795b25b6feedcfa71cc2fe58b378165";

        bytes memory e   = hex"0000000000000000000000000000000000000000000000000000000000000000"
                           hex"0000000000000000000000000000000000000000000000000000000000000000"
                           hex"0000000000000000000000000000000000000000000000000000000000000000"
                           hex"0000000000000000000000000000000000000000000000000000000000010001";

        require(RsaVerify.pkcs1Sha256(hash, sig, e, n), "signature verification failed");

        return true;

    }

    // pubSignals
    // SHA256(jwt) + Poseidon(sub) + iss + nonce + aud + iat + exp
    // bit array     one uint        byte array
    // 256           1               34    8       32    10    10
    function verify(bytes memory sig, uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[PUB_SIGNAL_LENGTH] memory _pubSignals) public returns (bool) {
        // 1. verify the ZK proof
        require(Verifier(zkVerify).verifyProof(_pA, _pB, _pC, _pubSignals), "ZK verify failed");

        // 2. verify the RSA signature
        bytes32 hash = extractHashFromPubSignal(_pubSignals);

        // TODO: instead of using fixed values, fetch from another contract (e.g., oracle)
        bytes memory n =    hex"b11e042ac1890495b395065fc7e033e488328563a8e1d7846373c069d13d9234"
                            hex"1ccb18f9cdc4d269ee2b07a622398b44cea8dc7be757869b9bc634bfa25af49f"
                            hex"4a6e0913749bbbb91e18a6d36f7f7f580dd874287dc091b4963873a56be71929"
                            hex"ae6492c64d76eed60a2755fef3abf324b3d1da9dd5524ce74e0b2410fe5bc6f1"
                            hex"d5ca3f35e0d40b85d32614024ec2ef54baeda8184e1307722266048263c80076"
                            hex"de187c25ea15e2c158f3bddc95703dd5384cddf044c4f0133fdbcb9655dbd8e0"
                            hex"f0e9f6581584b7a44be4164483f331cba396fd833f72c2afafc8ab24c4eff2ce"
                            hex"15f868b33b6154402754450c9f087c83f795b25b6feedcfa71cc2fe58b378165";

        bytes memory e   = hex"0000000000000000000000000000000000000000000000000000000000000000"
                           hex"0000000000000000000000000000000000000000000000000000000000000000"
                           hex"0000000000000000000000000000000000000000000000000000000000000000"
                           hex"0000000000000000000000000000000000000000000000000000000000010001";

        require(RsaVerify.pkcs1Sha256(hash, sig, e, n), "signature verification failed");

        // 3. verify claims except subject ID
        verifyClaims(_pubSignals);

        // 4. verify subject ID
        // TODO: implement this
        //bytes32 poseidon = bytes32(_pubSignals[0:256]);

        return true;
    }

    function verifyClaims(uint[PUB_SIGNAL_LENGTH] memory uintArray) public view returns (bool) {
        bytes memory b = new bytes(MASKED_JWT_LEN);
        uint masked_len = MASKED_JWT_LEN / NUM_BITS + 1;

        for (uint256 i = 0; i < masked_len; i++) {
            bytes32 b32 = bytes32(uintArray[PUB_SIGNAL_JWT_HASH_LENGTH + PUB_SIGNAL_SUB_HASH_LENGTH + i]);
            bytes memory bs = abi.encodePacked(b32);
            for (uint j = 0; j < NUM_BITS && i*NUM_BITS + j < MASKED_JWT_LEN; j++) {
                b[i*NUM_BITS + j] = bs[1 + j];
            }
        }

        string memory json = string(b);

        uint returnValue;
        JsmnSolLib.Token[] memory tokens;
        // TODO: set proper number for parse
        (returnValue, tokens, ) = JsmnSolLib.parse(json, 10);
        // TODO: Fix returnValue == JsmnSolLib.RETURN_ERROR_NO_MEM
        //require(returnValue == JsmnSolLib.RETURN_SUCCESS, "failed to parse masked JWT");

        JsmnSolLib.Token memory t;
        string memory key;
        bool keyFound = false;

        // TODO: refactor key-value parsing logic
        for (uint8 i = 0; i < tokens.length; i++) {
            t = tokens[i];
            if (t.jsmnType == JsmnSolLib.JsmnType.STRING || t.jsmnType == JsmnSolLib.JsmnType.PRIMITIVE) {
                if (!keyFound) {
                    key = JsmnSolLib.getBytes(json, t.start, t.end);
                    keyFound = true;
                } else {
                    if (keccak256(bytes(key)) != keccak256("sub") && claims[key].length > 0) {
                        require(keccak256(claims[key]) == keccak256(bytes(JsmnSolLib.getBytes(json, t.start, t.end))), "claim verification failed");
                    }
                    if (keccak256(bytes(key)) == keccak256("iat")) {
                        // TODO: implement this
                    }
                    if (keccak256(bytes(key)) == keccak256("exp")) {
                        // TODO: implement this
                    }
                    keyFound = false;
                }
            }
        }
        return true;
    }

    function extractHashFromPubSignal(uint[PUB_SIGNAL_LENGTH] memory bits) public pure returns (bytes32) {

        return bytes32(uint256 (uint128 (bits[0])) << 128 | uint128 (bits[1]));
    }
}
