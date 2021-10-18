// (c) 2021 Privacy Research, LLC https://privacyresearch.io,  GPL-v3-only: see LICENSE file.

import { hexToBytes } from '@privacyresearch/ed25519-ts/lib/serialization'
import { VerifiableClientContextImpl } from '../contexts/verifiable-client-context'
import { VerifiableServerContextImpl } from '../contexts/verifiable-server-context'
import { ristretto255SHA512Ciphersuite } from '@privacyresearch/noble-ciphersuite-r255s256'
import { numberArrayXOR, OPRFMode } from '../specification-utils'

const ciphersuite = ristretto255SHA512Ciphersuite(OPRFMode.Verified)

describe('Ristretto RFC tests', () => {
    test('A.1.2 test key derivation', () => {
        //     seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
        //     skSm = ac37d5850510299406ea8eb8fa226a7bfc2467a4b070d6c7bf667948b9600b00
        //     pkSm = 0c0254e22063cae3e1bae02fb6fa20882664a117c0278eda6bda3372c0dd9860
        const seed = hexToBytes('a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3')
        const skSm = hexToBytes('ac37d5850510299406ea8eb8fa226a7bfc2467a4b070d6c7bf667948b9600b00')
        const pkSm = hexToBytes('0c0254e22063cae3e1bae02fb6fa20882664a117c0278eda6bda3372c0dd9860')

        expect(seed.length).toEqual(32)
        const { skS, pkS } = ciphersuite.GG.deriveKeyPair(seed)
        const skSBytes = ciphersuite.GG.serializeScalar(skS)
        const pkSBytes = ciphersuite.GG.serializeElement(pkS)
        expect(skSBytes.length).toEqual(32)
        expect(pkSBytes.length).toEqual(32)

        expect(skSBytes).toEqual(skSm)
        expect(pkSBytes).toEqual(pkSm)
    })

    // Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
    // Info = 7465737420696e666f
    // Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0d50f,
    //     533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0c
    // BlindedElement = c24645d6378a4a86ec4682a8d86f368b1e7db870fd709a45102492bcdc17e904,
    //     0e5ec78f839a8b6e86999bc180602690a4daae57bf5d7f827f3d402f56cc6c51
    // EvaluationElement = 3afe48eab00493eb1b073e95f57a456cde9aefe463dd1e6d0144bf6e99ce411c,
    //     daaf9421318fd2c7fcdf369cb348748cf4dd177cce30ee4d13ceb1644b85b653
    // Proof = 601381ecbe127ada04c057b8b1fc21d912f71e49252780dd0d0ac768b233ce035f9b489a994c1d14b92d603ebcffee4f5cfadc953f69bb62648c6e662613ae00
    // ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a9706137886dce08
    // Output = 4b2ff4c984985829c3cd9d90c255cdc0d6b61c4c0aafa9215769d51cf7deb01472ba945928a8305e010f12b7dcc75a9dc2460439e6297d57dc2ce7ca0abaae1a,
    //     fe1fb7fa49c37dc7cd31d64859b4a2e6ae0cef294f2764e6f12f7d809f218047d1fde147cf69807b8971fb2c316eb572be2b5bf491813bfec0a20668d6d07b0b

    const vectorsA123 = {
        seed: hexToBytes('a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'),
        skS: hexToBytes('ac37d5850510299406ea8eb8fa226a7bfc2467a4b070d6c7bf667948b9600b00'),
        pkS: hexToBytes('0c0254e22063cae3e1bae02fb6fa20882664a117c0278eda6bda3372c0dd9860'),
        input: [hexToBytes('00'), hexToBytes('5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a')],
        info: hexToBytes('7465737420696e666f'),
        blind: [
            hexToBytes('80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0d50f'),
            hexToBytes('533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0c'),
        ],
        blindedElement: [
            hexToBytes('c24645d6378a4a86ec4682a8d86f368b1e7db870fd709a45102492bcdc17e904'),
            hexToBytes('0e5ec78f839a8b6e86999bc180602690a4daae57bf5d7f827f3d402f56cc6c51'),
        ],
        evaluatedElement: [
            hexToBytes('3afe48eab00493eb1b073e95f57a456cde9aefe463dd1e6d0144bf6e99ce411c'),
            hexToBytes('daaf9421318fd2c7fcdf369cb348748cf4dd177cce30ee4d13ceb1644b85b653'),
        ],
        proof: hexToBytes(
            '601381ecbe127ada04c057b8b1fc21d912f71e49252780dd0d0ac768b233ce035f9b489a994c1d14b92d603ebcffee4f5cfadc953f69bb62648c6e662613ae00'
        ),
        proofRandomScalar: hexToBytes('3af5aec325791592eee4a8860522f8444c8e71ac33af5186a9706137886dce08'),
        output: [
            hexToBytes(
                '4b2ff4c984985829c3cd9d90c255cdc0d6b61c4c0aafa9215769d51cf7deb01472ba945928a8305e010f12b7dcc75a9dc2460439e6297d57dc2ce7ca0abaae1a'
            ),
            hexToBytes(
                'fe1fb7fa49c37dc7cd31d64859b4a2e6ae0cef294f2764e6f12f7d809f218047d1fde147cf69807b8971fb2c316eb572be2b5bf491813bfec0a20668d6d07b0b'
            ),
        ],
    }
    type VerifiableBatchSize2Vector = typeof vectorsA123

    function verifiableServerContextBatchSize1Evaluate(v: VerifiableBatchSize2Vector) {
        const { info, blindedElement, seed } = v

        const vEvaluatedElement = v.evaluatedElement

        const { skS } = ciphersuite.GG.deriveKeyPair(seed)

        const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

        const evaluatedElement = serverContext.evaluate(blindedElement[0], info)
        expect(evaluatedElement).toEqual(vEvaluatedElement[0])
    }

    function verifiableClientContextFinalize(v: VerifiableBatchSize2Vector) {
        const { input, info, blind, evaluatedElement } = v
        const vOutput = v.output

        const pkS = ciphersuite.GG.deserializeElement(v.pkS)

        const clientContext = new VerifiableClientContextImpl(ciphersuite, pkS)

        const output = clientContext.finalize(input[0], blind[0], evaluatedElement[0], info)
        expect(output).toEqual(vOutput[0])
    }

    function verifiableModeFullProtocol(v: VerifiableBatchSize2Vector) {
        const { seed, input, info } = v

        const vOutput = v.output

        const { skS, pkS } = ciphersuite.GG.deriveKeyPair(seed)

        const clientContext = new VerifiableClientContextImpl(ciphersuite, pkS)
        const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

        const blindResults = input.map((i) => clientContext.blind(i))
        const blinds = blindResults.map((r) => r.blind)
        const blindedElements = blindResults.map((r) => r.blindedElement)

        const evalResults = serverContext.verifiableEvaluateBatch(blindedElements, info)

        const output = clientContext.verifiableFinalizeBatch(
            input,
            blinds,
            evalResults.evaluatedElements,
            blindedElements,
            evalResults.proof,
            info
        )
        expect(output).toEqual(vOutput)
    }

    function verifiableModeFullEvaluate(v: VerifiableBatchSize2Vector) {
        const { seed, input, info } = v

        const vOutput = v.output

        const { skS } = ciphersuite.GG.deriveKeyPair(seed)
        const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

        const output = serverContext.fullEvaluate(input[0], info)
        expect(output).toEqual(vOutput[0])
    }

    function verifiableModeVerifyFinalize(v: VerifiableBatchSize2Vector) {
        const { seed, input, info, output } = v
        const { skS } = ciphersuite.GG.deriveKeyPair(seed)
        const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

        const valid = serverContext.verifyFinalize(input[0], output[0], info)
        expect(valid).toBe(true)
    }

    function verifiableClientContextAcceptProof(v: VerifiableBatchSize2Vector) {
        const { seed, input, info, blind, evaluatedElement, blindedElement } = v

        expect(v.proof.length).toEqual(64)
        const proof = { c: v.proof.slice(0, 32), s: v.proof.slice(32, 64) }
        const mask = [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
        const badProof = { c: proof.c, s: numberArrayXOR(proof.s, mask) }

        const { pkS } = ciphersuite.GG.deriveKeyPair(seed)
        const badPKS = ciphersuite.GG.add(ciphersuite.GG.G, pkS)
        const clientContext = new VerifiableClientContextImpl(ciphersuite, pkS)
        const badPKClientContext = new VerifiableClientContextImpl(ciphersuite, badPKS)
        expect(() => {
            clientContext.verifiableFinalizeBatch(input, blind, evaluatedElement, blindedElement, proof, info)
        }).not.toThrow()
        expect(() => {
            clientContext.verifiableFinalizeBatch(input, blind, evaluatedElement, blindedElement, badProof, info)
        }).toThrow()
        expect(() => {
            badPKClientContext.verifiableFinalizeBatch(input, blind, evaluatedElement, blindedElement, badProof, info)
        }).toThrow()
    }

    test('A.1.2.3 Test Vector 2 Batch Size 2: ServerVerifiableServerContextContext::evaluate', () => {
        verifiableServerContextBatchSize1Evaluate(vectorsA123)
    })

    test('A.1.2.3 Test Vector 2 Batch Size 2: ClientContext::finalize', () => {
        verifiableClientContextFinalize(vectorsA123)
    })

    test('A.1.2.3 Test Vector 2 Batch Size 2: Full run with random blinds', () => {
        verifiableModeFullProtocol(vectorsA123)
    })

    test('A.1.2.3 Test Vector 2 Batch Size 2: VerifiableServerContext::FullEvaluate', () => {
        verifiableModeFullEvaluate(vectorsA123)
    })

    test('A.1.2.3 Test Vector 2 Batch Size 2: VerifiableServerContext::VerifyFinalize', () => {
        verifiableModeVerifyFinalize(vectorsA123)
    })

    test('A.1.2.3 Test Vector 2 Batch Size 2: Test verification', () => {
        verifiableClientContextAcceptProof(vectorsA123)
    })
})
