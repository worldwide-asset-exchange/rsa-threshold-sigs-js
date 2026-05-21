# RSA Threshold signatures library

A JavaScript implementation of threshold RSA signatures based on [Victor Shoup's "Practical Threshold Signatures" (Eurocrypt 2000)](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf)

### Install dependencies

```bash
$ yarn install
```

### Sample Script

1. Generate key pair and split it to multiple shares

```bash
$ yarn ts-node script/generateKey.ts
```

Output generated key are stored in [here](generatedKeys/threshold-keys.json)

2. Run sample code to sign with share key

```bash
$ yarn ts-node script/signShare.ts
```

### Run test

```bash
$ yarn test
```
