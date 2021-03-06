# VOPRF - Verifiable Oblivious Pseudorandom Functions

This package implements v07 of [the Internet-Draft OPRF protocol](https://tools.ietf.org/html/draft-irtf-cfrg-voprf). It
provides both Base and Verifiable modes of operation.

## Implementation Status

This protocol implementation is generic, allowing users to create server and client contexts using their own
implementations of ciphersuites. So if a user implements, for example, a Decaf448-SHAKE256 ciphersuite then
this library can use it to execute the VOPRF protocol. This provides flexibility to users as well as a
degree of future-proofing - as better ciphersuite implementations arise they will be usable (almost) out
of the box with this library.

With that said, standard ciphersuite implementations are still needed. The table below shows the current state
of support.

| _Ciphersuite_              | _Supported_ | _Curve Implementation_                                                            | _Notes_                                      |
| -------------------------- | ----------- | --------------------------------------------------------------------------------- | -------------------------------------------- |
| OPRF(Ristretto255, SHA512) | ✔️          | [@privacyresearch/ed25519-ts](https://github.com/privacyresearchgroup/ed25519-ts) | Configurable BigInt and Hash implementations |
| OPRF(Decaf448, SHAKE-256)  | ❌          |                                                                                   |                                              |
| OPRF(P-256, SHA-256)       | ❌          |                                                                                   |                                              |
| OPRF(P-384, SHA-384)       | ❌          |                                                                                   |                                              |
| OPRF(P-521, SHA-512)       | ❌          |                                                                                   |                                              |

## Installation

Install with `yarn`:

```
yarn add @privacyresearch/oprf-ts
```

## Usage

In the examples below we work with the Ristretto255-SHA512 ciphersuite. This ciphersuite uses the
[@privacyresearch/ed25519-ts](https://github.com/privacyresearchgroup/ed25519-ts) implementation of the Ristretto
group, which allows programmers to choose their own implementation of arbitrary precision integers - something
that is particularly useful when working on platforms that do not have native `bigint` support (such as React Native).

To emphasize flexibility, these examples will use the [JSBI](https://github.com/GoogleChromeLabs/jsbi) arbitrary precision
arithmetic library.

### Creating the ciphersuite

Every program with this library will start by creating a ciphersuite. Here we create a Ristretto255-SHA512 ciphersuite
using the JSBI library for arithmetic.

```typescript
import { makeED } from '@privacyresearch/ed25519-ts'
import JSBI from 'jsbi'
const ed = makeED(JSBI)
const ciphersuite = ristretto255SHA512Ciphersuite<JSBI>(ed, OPRFMode.Base)
```

### Creating or Importing a Keypair

Given `seed`, an array of random bytes with sufficient entropy, derive a keypair with secret key `skS` and public key `pkS`
as follows:

```typescript
// skS is a Scalar, pkS is a group element
const { skS, pkS } = ciphersuite.GG.deriveKeyPair(seed)
```

With a ciphersuite and keypair in hand, we can begin the protocol.

### Base Mode

#### Client Protocol in Base Mode

In base mode we do not perform verification, so the server public key, `pkS`, is not needed. Below we see a full client
run of the OPRF protocol. It consists of four steps:

1. Create a `ClientContext`.
2. Blind input
3. Send the blinded element to the server along with public info.
4. Unblind and finalize the server response.

```typescript
import { ClientContextImpl } from '@privacyresearch/oprf-ts'
const clientContext = new ClientContextImpl(ciphersuite)

let input: PrivateInput // Uint8Array
let info: PublicInput // Uint8Array

const { blind, blindedElement } = clientContext.blind(input)

// This is pseudocode - you'll know how to call your server!
const evaluatedElement = await callServer(blindedElement, info)

const output = clientContext.finalize(input, blind, evaluatedElement, info)
```

#### Server Protocol in Base Mode

The server will need to be initialized with its secret key, `skS`. Here is how the
server will handle the client's call

```typescript
import { ServerContextImpl } from '@privacyresearch/oprf-ts'

const serverContext = new ServerContextImpl(ciphersuite, skS)

const { evaluatedElement } = serverContext.evaluate(blindedElement, info)

// Now return `evaluatedElement` to the client
```

### Verifiable Mode

Verifiable mode is almost identical to the base mode for the programmer. Since all verification
is performed by this library, the only differences will be small differences in function and class names,
and the need for the server to return a verification proof with its response.

#### Client Protocol in Verifiable Mode

In verifiable mode, the client needs to be initialized with the server's public key, `pkS`, in order
to perform verification.

```typescript
import { VerifiableClientContextImpl } from '@privacyresearch/oprf-ts'
const clientContext = new VerifiableClientContextImpl(ciphersuite, pkS)

let input: PrivateInput // Uint8Array
let info: PublicInput // Uint8Array

const { blind, blindedElement } = clientContext.blind(input)

// This is pseudocode - you'll know how to call your server!
const { evaluatedElement, proof } = await callServer(blindedElement, info)

// This will throw an `Error` if verification fails
const output = clientContext.verifiableFinalize(input, blind, evaluatedElement, info)
```

#### Server Protocol in Verifiable Mode

The server will need to be initialized with its secret key, `skS`. Here is how the
server will handle the client's call

```typescript
import { VerifiableServerContextImpl } from '@privacyresearch/oprf-ts'

const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

const { evaluatedElement, proof } = serverContext.verifiableEvaluate(blindedElement, info)

// Now return `{evaluatedElement, proof}` to the client
```

### Batch Processing

Multiple inputs that use the same public info can be evaluated in a single batch call that returns a
constant-sized proof. To do this, use the methods `verifiableEvaluateBatch` on the server and
`verifiableFinalizeBatch` on the client:

```typescript
import { VerifiableClientContextImpl, VerifiableServerContextImpl } from '@privacyresearch/oprf-ts'
const clientContext = new VerifiableClientContextImpl(ciphersuite, pkS)
const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

let inputs: PrivateInput[] // Uint8Array[]
let info: PublicInput // Uint8Array

const blindResults = inputs.map((input) => clientContext.blind(input))
const blinds = blindResults.map((br) => br.blind)
const blindedElements = blindResults.map((blindedElement) => br.blindedElement)

// Just for domonstration - the server will really be somewhere else
const { evaluatedElements, proof } = serverContext.verifiableEvaluateBatch(blindedElements, info)

// This will throw an `Error` if verification fails
const output = clientContext.verifiableFinalizeBatch(inputs, blinds, evaluatedElements, blindedElements, proof, info)
```

## Implementing New Ciphersuites

A good place to get started when developing a new ciphersuite for use with this library is the [Privacy Research
`ciphersuites` repository](https://github.com/privacyresearchgroup/ciphersuites). There you will find

- Type definitions for groups, scalars, and ciphersuites
- Implementations of standard functions such as `I2OSP`, `OS2IP`, `CT_EQUAL`, and `expand_message_xmd`
- Ciphersuite implementations, including `@privacyresearch/noble-restretto255-sha256`, an implementation
  of the `OPRF(Ristretto255, SHA256)` ciphersuite based on [`noble-ed25519`](https://github.com/paulmillr/noble-ed25519).
  To see this ciphersuite in use, look at this [unit test](https://github.com/privacyresearchgroup/oprf-ts/blob/main/src/__test__/rfc-ristretto-batch-verifiable-vectors-noble-ciphersuite.test.ts).

  _This implementation uses the native `bigint` and is much faster than the `JSBI` implementation described above. If `bigint`s are available and acceptable for your application, `nobe-ed25519` is preferred._

## License

(c) 2021 Privacy Research, LLC [(https://privacyresearch.io)](https://privacyresearch.io), see LICENSE file.
