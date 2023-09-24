// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "./izkverify.sol";
import "./rsa.sol";
import "hardhat/console.sol";

contract JWT {

    uint public constant NUMBER_OF_CLAIMS = 5;
    string[] public CLAIM_NAMES = ["iss", "nonce", "aud", "iat", "exp"];
    uint public PUB_SIGNAL_CLAIMS_LENGTH = 34 + 8 + 32 + 10 + 10;
    uint public PUB_SIGNAL_JWT_HASH_LENGTH = 256;
    uint public PUB_SIGNAL_SUB_HASH_LENGTH = 1;
    uint public PUB_SIGNAL_LENGTH = PUB_SIGNAL_JWT_HASH_LENGTH + PUB_SIGNAL_SUB_HASH_LENGTH + PUB_SIGNAL_CLAIMS_LENGTH;
    address public zkVerify;
    mapping (string => bytes) public claims;
    mapping (string => ClaimInfo) public claimInfo;

    struct ClaimInfo {
        uint offset;
        uint len;
    }
    
    constructor(address _zkVerify, string[] memory _claimNames, bytes[] memory _claimValues, uint[] memory _claimOffsets) {
        zkVerify = _zkVerify;
        assert(_claimNames.length == NUMBER_OF_CLAIMS);
        assert(_claimValues.length == NUMBER_OF_CLAIMS);
        assert(_claimOffsets.length == NUMBER_OF_CLAIMS);

        uint claimsLen = 0;
        for (uint i = 0; i < NUMBER_OF_CLAIMS; i++) {
            claims[_claimNames[i]] = _claimValues[i];
            claimInfo[_claimNames[i]] = ClaimInfo(_claimOffsets[i], _claimValues[i].length);
            claimsLen += _claimValues[i].length;
        }
        require(claimsLen == PUB_SIGNAL_CLAIMS_LENGTH, "claim lengths do not add up to known value");
    }

    // Dummy function to measure performance of ZK proof verification
    function returnTrue(bytes calldata, uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[351] memory) public pure returns (bool) {
        return true;
    }

    // Dummy function to measure performance of ZK proof verification
    function rsaVerify(bytes calldata sig, uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[351] memory _pubSignals) public view returns (bool) {
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
    function verify(bytes memory sig, uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[351] memory _pubSignals) public view returns (bool) {
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
        verifyClaims(extractClaimBytesFromPubSignal(_pubSignals));

        // 4. verify subject ID
        // TODO: implement this
        //bytes32 poseidon = bytes32(_pubSignals[0:256]);

        // 5. verify timestamps, iat and exp
        // TODO: implement this
        return true;
    }

    function verifyClaims(bytes memory _data) internal view {
        for (uint8 i = 0; i < NUMBER_OF_CLAIMS; i++) {
            uint offset = claimInfo[CLAIM_NAMES[i]].offset;
            uint len = claimInfo[CLAIM_NAMES[i]].len;
            bytes memory claim = new bytes(len);
            for (uint j = 0; j < len; j++) {
                claim[j] = _data[offset + j];
            }
            require(keccak256(claim) == keccak256(claims[CLAIM_NAMES[i]]), "claim verification failed");
        }
    }

    function extractClaimBytesFromPubSignal(uint[351] memory uintArray) public view returns (bytes memory) {
        bytes memory result = new bytes(PUB_SIGNAL_CLAIMS_LENGTH); // 32 bytes per uint

        for (uint256 i = 0; i < PUB_SIGNAL_CLAIMS_LENGTH; i++) {
            result[i] = bytes1(uint8(uintArray[257 + i]));
        }

        return result;
    }

    function extractHashFromPubSignal(uint[351] memory bits) public pure returns (bytes32) {

        bytes memory byteArray = new bytes(32);

        for (uint i = 0; i < 256; i += 8) {
            uint8 byteValue = 0;
            for (uint8 j = 0; j < 8; j++) {
                byteValue |= uint8(bits[i + 8 - j - 1] & 1) << j;
            }
            byteArray[i / 8] = bytes1(byteValue);
        }

        bytes32 hash;
        assembly {
            hash := mload(add(byteArray, 32))
        }

        return hash;
    }
}