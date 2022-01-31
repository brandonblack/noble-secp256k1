# noble-secp256k1 ![Node CI](https://github.com/paulmillr/noble-secp256k1/workflows/Node%20CI/badge.svg) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

[Fastest](#speed) JS implementation of [secp256k1](https://www.secg.org/sec2-v2.pdf),
an elliptic curve that could be used for asymmetric encryption,
ECDH key agreement protocol and signature schemes. Supports deterministic **ECDSA** from RFC6979 and **Schnorr** signatures from [BIP0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

[**Audited**](#security) with crowdfunding by an independent security firm. Tested against thousands of test vectors from a different library. Check out [the online demo](https://paulmillr.com/ecc) and blog post: [Learning fast elliptic-curve cryptography in JS](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/)

### This library belongs to *noble* crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, one small file
- Easily auditable TypeScript/JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519),
  [bls12-381](https://github.com/paulmillr/noble-bls12-381),
  [hashes](https://github.com/paulmillr/noble-hashes)

## Usage

Use NPM in node.js / browser, or include single file from
[GitHub's releases page](https://github.com/paulmillr/noble-secp256k1/releases):

> npm install @noble/secp256k1

```js
// Common.js and ECMAScript Modules (ESM)
import * as secp from "@noble/secp256k1";
// If you're using single file, use global variable instead:
// nobleSecp256k1

(async () => {
  // You pass a hex string, or Uint8Array
  const privateKey = "6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e";
  const message = "hello world";
  const messageHash = await secp.utils.sha256(message);
  const publicKey = secp.getPublicKey(privateKey);
  const signature = await secp.sign(messageHash, privateKey);
  const isSigned = secp.verify(signature, messageHash, publicKey);

  // Sigs with improved security (see README)
  const signatureE = await secp.sign(messageHash, privateKey, { extraEntropy: true });

  // Malleable signatures, compatible with openssl
  const signatureM = await secp.sign(messageHash, privateKey, { canonical: false });

  // If you need hex strings
  const hex = secp.utils.bytesToHex;
  console.log(hex(publicKey));

  // Supports Schnorr signatures
  const rpub = secp.schnorr.getPublicKey(privateKey);
  const rsignature = await secp.schnorr.sign(message, privateKey);
  const risSigned = await secp.schnorr.verify(rsignature, message, rpub);
})();
```

To use the module with [Deno](https://deno.land),
you will need [import map](https://deno.land/manual/linking_to_external_code/import_maps):

- `deno run --import-map=imports.json app.ts`
- app.ts: `import * as secp from "https://deno.land/x/secp256k1/mod.ts";`
- imports.json: `{"imports": {"crypto": "https://deno.land/std@0.119.0/node/crypto.ts"}}`

## API

- [`getPublicKey(privateKey)`](#getpublickeyprivatekey)
- [`sign(msgHash, privateKey)`](#signmsghash-privatekey)
- [`verify(signature, msgHash, publicKey)`](#verifysignature-msghash-publickey)
- [`getSharedSecret(privateKeyA, publicKeyB)`](#getsharedsecretprivatekeya-publickeyb)
- [`recoverPublicKey(hash, signature, recovery)`](#recoverpublickeyhash-signature-recovery)
- [`schnorr.getPublicKey(privateKey)`](#schnorrgetpublickeyprivatekey)
- [`schnorr.sign(message, privateKey)`](#schnorrsignmessage-privatekey)
- [`schnorr.verify(signature, message, publicKey)`](#schnorrverifysignature-message-publickey)
- [Utilities](#utilities)

##### `getPublicKey(privateKey)`
```typescript
function getPublicKey(privateKey: Uint8Array | string | bigint, isCompressed = false): Uint8Array;
```

Creates public key for the corresponding private key. Could return compressed 33-byte keys, or
uncompressed 65-byte keys.

Internally, it does `Point.BASE.multiply(privateKey)`. If you need actual `Point` instead of
`Uint8Array`, use `Point.fromPrivateKey(privateKey)`.

##### `sign(msgHash, privateKey)`
```typescript
function sign(msgHash: Uint8Array | string, privateKey: Uint8Array | string, opts?: Options): Promise<Uint8Array>;
function sign(msgHash: Uint8Array | string, privateKey: Uint8Array | string, opts?: Options): Promise<[Uint8Array, number]>;
```

Generates low-s deterministic ECDSA signature as per RFC6979.

- `msgHash: Uint8Array | string` - message hash which would be signed
- `privateKey: Uint8Array | string | bigint` - private key which will sign the hash
- `options?: Options` - *optional* object related to signature value and format with following keys:
    - `recovered: boolean = false` - whether the recovered bit should be included in the result. In this case, the result would be an array of two items.
    - `canonical: boolean = true` - whether a signature `s` should be no more than 1/2 prime order.
      `true` (default) makes signatures compatible with libsecp256k1,
      `false` makes signatures compatible with openssl
    - `der: boolean = true` - whether the returned signature should be in DER format. If `false`, it would be in Compact format (32-byte r + 32-byte s)
    - `extraEntropy: Uint8Array | string | true` - additional entropy `k'` for deterministic signature, follows section 3.6 of RFC6979. When `true`, it would automatically be filled with 32 bytes of cryptographically secure entropy. **Strongly recommended** to pass `true` to improve security:
        - Schnorr signatures are doing it every time
        - It would help a lot in case there is an error somewhere in `k` generation. Exposing `k` could leak private keys
        - If the entropy generator is broken, signatures would be the same as they are without the option
        - Signatures with extra entropy would have different `r` / `s`, which means they
        would still be valid, but may break some test vectors if you're cross-testing against other libs

The function is asynchronous because we're utilizing built-in HMAC API to not rely on dependencies.

```typescript
function signSync(msgHash: Uint8Array | string, privateKey: Uint8Array | string, opts?: Options): Uint8Array | [Uint8Array, number];
```

`signSync` counterpart could also be used, you need to set `utils.hmacSha256Sync` to a function with signature `key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array`. Example with `noble-hashes` package:

```ts
import { hmac } = from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
secp256k1.utils.hmacSha256Sync = (key: Uint8Array, ...msgs: Uint8Array[]) => {
  const h = hmac.create(sha256, key);
  msgs.forEach(msg => h.update(msg));
  return h.digest();
};

// Can be used now
secp256k1.signSync(msgHash, privateKey)
```

##### `verify(signature, msgHash, publicKey)`
```typescript
function verify(signature: Uint8Array | string, msgHash: Uint8Array | string, publicKey: Uint8Array | string): boolean
function verify(signature: Signature, msgHash: Uint8Array | string, publicKey: Point): boolean
```
- `signature: Uint8Array | string | { r: bigint, s: bigint }` - object returned by the `sign` function
- `msgHash: Uint8Array | string` - message hash that needs to be verified
- `publicKey: Uint8Array | string | Point` - e.g. that was generated from `privateKey` by `getPublicKey`
- `options?: Options` - *optional* object related to signature value and format
  - `strict: boolean = true` - whether a signature `s` should be no more than 1/2 prime order.
    `true` (default) makes signatures compatible with libsecp256k1,
    `false` makes signatures compatible with openssl
- Returns `boolean`: `true` if `signature == hash`; otherwise `false`

##### `getSharedSecret(privateKeyA, publicKeyB)`
```typescript
function getSharedSecret(privateKeyA: Uint8Array | string | bigint, publicKeyB: Uint8Array | string | Point): Uint8Array;
```

Computes ECDH (Elliptic Curve Diffie-Hellman) shared secret between a private key and a different public key.

- To get Point instance, use `Point.fromHex(publicKeyB).multiply(privateKeyA)`.
- If you have one public key you'll be creating lots of secrets against,
  consider massive speed-up by using precomputations:

    ```js
    const pub = secp.utils.precompute(8, publicKeyB);
    // Use pub everywhere instead of publicKeyB
    getSharedSecret(privKey, pub); // Now 12x faster
    ```

##### `recoverPublicKey(hash, signature, recovery)`
```typescript
function recoverPublicKey(msgHash: Uint8Array | string, signature: Uint8Array | string, recovery: number): Uint8Array | undefined;
```
- `msgHash: Uint8Array | string` - message hash which would be signed
- `signature: Uint8Array | string | { r: bigint, s: bigint }` - object returned by the `sign` function
- `recovery: number` - recovery bit returned by `sign` with `recovered` option
  Public key is generated by doing scalar multiplication of a base Point(x, y) by a fixed
  integer. The result is another `Point(x, y)` which we will by default encode to hex Uint8Array.
  If signature is invalid - function will return `undefined` as result.

To get Point instance, use `Point.fromSignature(hash, signature, recovery)`.

##### `schnorr.getPublicKey(privateKey)`
```typescript
function schnorrGetPublicKey(privateKey: Uint8Array | string): Uint8Array;
```

Calculates 32-byte public key from a private key.

*Warning:* it is incompatible with non-schnorr pubkey. Specifically, its *y* coordinate may be flipped. See [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) for clarification.

##### `schnorr.sign(message, privateKey)`
```typescript
function schnorrSign(message: Uint8Array | string, privateKey: Uint8Array | string, auxilaryRandom?: Uint8Array): Promise<Uint8Array>;
```

Generates Schnorr signature as per BIP0340. Asynchronous, so use `await`.

- `message: Uint8Array | string` - message (not hash) which would be signed
- `privateKey: Uint8Array | string | bigint` - private key which will sign the hash
- `auxilaryRandom?: Uint8Array` — optional 32 random bytes. By default, the method gathers cryptogarphically secure entropy
- Returns Schnorr signature in Hex format.

##### `schnorr.verify(signature, message, publicKey)`
```typescript
function schnorrVerify(signature: Uint8Array | string, message: Uint8Array | string, publicKey: Uint8Array | string): boolean
```
- `signature: Uint8Array | string | { r: bigint, s: bigint }` - object returned by the `sign` function
- `message: Uint8Array | string` - message (not hash) that needs to be verified
- `publicKey: Uint8Array | string | Point` - e.g. that was generated from `privateKey` by `getPublicKey`
- Returns `boolean`: `true` if `signature == hash`; otherwise `false`

#### Utilities

secp256k1 exposes a few internal utilities for improved developer experience:

```typescript
const utils: {
  // Can take 40 or more bytes of uniform input e.g. from CSPRNG or KDF
  // and convert them into private key, with the modulo bias being neglible.
  // As per FIPS 186 B.1.1.
  hashToPrivateKey: (hash: Hex) => Uint8Array;
  // Returns `Uint8Array` of 32 cryptographically secure random bytes that can be used as private key
  randomPrivateKey: () => Uint8Array;
  // Checks private key for validity
  isValidPrivateKey(privateKey: PrivKey): boolean;

  // Returns `Uint8Array` of x cryptographically secure random bytes.
  randomBytes: (bytesLength?: number) => Uint8Array;
  // Converts Uint8Array to hex string
  bytesToHex: typeof bytesToHex;
  // Modular division over curve prime
  mod: (number: number | bigint, modulo = CURVE.P): bigint;
  sha256: (message: Uint8Array) => Promise<Uint8Array>;
  hmacSha256: (key: Uint8Array, ...messages: Uint8Array[]) => Promise<Uint8Array>;

  // You can set up your synchronous methods for `signSync` to work. The argument order is
  // identical to async methods from above
  sha256Sync: undefined;
  hmacSha256Sync: undefined;

  // 1. Returns cached point which you can use to pass to `getSharedSecret` or to `#multiply` by it.
  // 2. Precomputes point multiplication table. Is done by default on first `getPublicKey()` call.
  // If you want your first getPublicKey to take 0.16ms instead of 20ms, make sure to call
  // utils.precompute() somewhere without arguments first.
  precompute(windowSize?: number, point?: Point): Point;
};

secp256k1.CURVE.P // Field, 2 ** 256 - 2 ** 32 - 977
secp256k1.CURVE.n // Order, 2 ** 256 - 432420386565659656852420866394968145599
secp256k1.Point.BASE // new secp256k1.Point(Gx, Gy) where
// Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240n
// Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;

// Elliptic curve point in Affine (x, y) coordinates.
secp256k1.Point {
  constructor(x: bigint, y: bigint);
  // Supports compressed and non-compressed hex
  static fromHex(hex: Uint8Array | string);
  static fromPrivateKey(privateKey: Uint8Array | string | number | bigint);
  static fromSignature(
    msgHash: Hex,
    signature: Signature,
    recovery: number | bigint
  ): Point | undefined {
  toRawBytes(isCompressed = false): Uint8Array;
  toHex(isCompressed = false): string;
  equals(other: Point): boolean;
  negate(): Point;
  add(other: Point): Point;
  subtract(other: Point): Point;
  // Constant-time scalar multiplication.
  multiply(scalar: bigint | Uint8Array): Point;
}
secp256k1.Signature {
  constructor(r: bigint, s: bigint);
  // DER encoded ECDSA signature
  static fromDER(hex: Uint8Array | string);
  // R, S 32-byte each
  static fromCompact(hex: Uint8Array | string);
  assertValidity(): void;
  hasHighS(): boolean; // high-S sigs cannot be produced using { canonical: true }
  toDERRawBytes(): Uint8Array;
  toDERHex(): string;
  toCompactRawBytes(): Uint8Array;
  toCompactHex(): string;
}
```

## Security

Noble is production-ready.

1. The library has been audited by an independent security firm cure53: [PDF](https://cure53.de/pentest-report_noble-lib.pdf). The audit has been [crowdfunded](https://gitcoin.co/grants/2451/audit-of-noble-secp256k1-cryptographic-library) by community with help of [Umbra.cash](https://umbra.cash).
2. The library has also been fuzzed by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz). You can run the fuzzer by yourself to check it.

We're using built-in JS `BigInt`, which is "unsuitable for use in cryptography" as [per official spec](https://github.com/tc39/proposal-bigint#cryptography). This means that the lib is potentially vulnerable to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack). But, *JIT-compiler* and *Garbage Collector* make "constant time" extremely hard to achieve in a scripting language. Which means *any other JS library doesn't use constant-time bigints*. Including bn.js or anything else. Even statically typed Rust, a language without GC, [makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security) for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones. Use low-level libraries & languages. Nonetheless we've hardened implementation of koblitz curve multiplication to be algorithmically constant time.

We however consider infrastructure attacks like rogue NPM modules very important; that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings. If your app uses 500 dependencies, any dep could get hacked and you'll be downloading malware with every `npm install`. Our goal is to minimize this attack vector.

## Speed

Benchmarks measured with Apple M1 on MacOS 12.

    getPublicKey(utils.randomPrivateKey()) x 6,216 ops/sec @ 160μs/op
    sign x 4,789 ops/sec @ 208μs/op
    verify x 923 ops/sec @ 1ms/op
    recoverPublicKey x 491 ops/sec @ 2ms/op
    getSharedSecret aka ecdh x 558 ops/sec @ 1790μs/op
    getSharedSecret (precomputed) x 7,105 ops/sec @ 140μs/op
    Point.fromHex (decompression) x 12,171 ops/sec @ 82μs/op
    schnorr.sign x 409 ops/sec @ 2ms/op
    schnorr.verify x 504 ops/sec @ 1ms/op

Compare to other libraries (`openssl` uses native bindings, not JS):

    elliptic#getPublicKey x 1,940 ops/sec
    sjcl#getPublicKey x 211 ops/sec

    elliptic#sign x 1,808 ops/sec
    sjcl#sign x 199 ops/sec
    openssl#sign x 4,243 ops/sec
    ecdsa#sign x 116 ops/sec
    bip-schnorr#sign x 60 ops/sec

    elliptic#verify x 812 ops/sec
    sjcl#verify x 166 ops/sec
    openssl#verify x 4,452 ops/sec
    ecdsa#verify x 80 ops/sec
    bip-schnorr#verify x 56 ops/sec

    elliptic#ecdh x 971 ops/sec


## Contributing

Check out a blog post about this library: [Learning fast elliptic-curve cryptography in JS](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/).

1. Clone the repository.
2. `npm install` to install build dependencies like TypeScript
3. `npm run compile` to compile TypeScript code
4. `npm run test` to run jest on `test/index.ts`

Special thanks to [Roman Koblov](https://github.com/romankoblov), who have helped to improve scalar multiplication speed.

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
