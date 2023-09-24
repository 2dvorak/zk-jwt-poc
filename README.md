# zk-jwt-poc

Verify JWT (OIDC id\_token) in smart contract, however privacy preserved with the aids of ZK

## Prerequisites
- [Node.js](https://nodejs.org/en/download) (tested with v16.19.1)
- [Circom](https://docs.circom.io/getting-started/installation/)

Also, we need `npx`.
```
$ npm install -g npx
```

The `powers of tau` file is used when generating zkey, so download one.
```
$ wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_19.ptau
```

Make sure to install node modules.
```
$ npm install
```

## Build
```
$ mkdir build
$ circom jwt.circom --r1cs --wasm -o ./build
```

## Run

Run below command to test JWT verification using ZK.

```
$ npx hardhat run jwt.js
```
The script includes the following steps:
1. Generate zkey from compiled ZK circuit
2. Calcuate witness
3. Generate ZK proof
4. Verify generated ZK proof (with snarkjs)
5. Generate solidity file for verifying JWT with ZK
6. Compile contracts
7. Deploy contracts
8. Verify JWT on-chain


The output shows times took in each steps.
```
Nothing to compile
init time:  914
zkey time:  58270
wtns time:  560
prove time:  4984
verify time:  190
sol time:  356
compile time:  38
deploy time:  1082
ZK verify time:  1679
(measure) dummy contract time:  34
(measure) RSA verify only time:  171
```


## TODO
- Verify Poseidon hash
- Verify timestamps
- Use oracles for JWKS and time
- Contract size (currently, the generated code size (~34500) exceeds 24576 bytes)
