// (c) 2021 Privacy Research, LLC https://privacyresearch.io,  GPL-v3-only: see LICENSE file.

import { makeED } from '@privacyresearch/ed25519-ts'
import { hexToBytes } from '@privacyresearch/ed25519-ts/lib/serialization'
import JSBI from 'jsbi'
import { ClientContextImpl } from '../contexts/base-client-context'
import { ServerContextImpl } from '../contexts/base-server-context'
import { ristretto255SHA512Ciphersuite } from '../ristretto255-sha512/ciphersuite'
import { OPRFMode } from '../specification-utils'

const ed = makeED(JSBI)
const ciphersuite = ristretto255SHA512Ciphersuite<JSBI>(ed, OPRFMode.Base)

describe('Ristretto RFC tests', () => {
    test('A.1.1 test key derivation', () => {
        const seed = hexToBytes('a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3')
        const skSm = hexToBytes('caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1701')

        expect(seed.length).toEqual(32)
        const { skS } = ciphersuite.GG.deriveKeyPair(seed)
        const skSBytes = ciphersuite.GG.serializeScalar(skS)
        expect(skSBytes.length).toEqual(32)

        expect(skSBytes).toEqual(skSm)
    })

    // Input = 00
    // Info = 7465737420696e666f
    // Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03
    // BlindedElement = fc20e03aff3a9de9b37e8d35886ade11ec7d85c2a1fb5bb0b1686c64e07ac467
    // EvaluationElement = 922e4c04b9f3b3e795d322a306c0ab9d96b667df9b949c052c8c75435a9dbf2f
    // Output = 9e857d0e8523b8eb9e995d455ae6ae19f75d85ac8b5df62c50616fb5aa0ced3da5646698089c36dead28f9ad8e489fc0ee1c8e168725c38ed50f3783a5c520ce
    const vectorsA111 = {
        seed: hexToBytes('a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'),
        skS: hexToBytes('caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1701'),
        input: hexToBytes('00'),
        info: hexToBytes('7465737420696e666f'),
        blind: hexToBytes('c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03'),
        blindedElement: hexToBytes('fc20e03aff3a9de9b37e8d35886ade11ec7d85c2a1fb5bb0b1686c64e07ac467'),
        evaluatedElement: hexToBytes('922e4c04b9f3b3e795d322a306c0ab9d96b667df9b949c052c8c75435a9dbf2f'),
        output: hexToBytes(
            '9e857d0e8523b8eb9e995d455ae6ae19f75d85ac8b5df62c50616fb5aa0ced3da5646698089c36dead28f9ad8e489fc0ee1c8e168725c38ed50f3783a5c520ce'
        ),
    }
    // Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
    // Info = 7465737420696e666f
    // Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b
    // BlindedElement = 483d4f39de5ff77fa0f9a0ad2334dd5bf87f2cda868539d21de67ce49e7d1536
    // EvaluationElement = 6eef6ee53c6fb17c77ae47e78bdca2e1094f98785e7b9a14f09be20797dad656
    // Output = b090b2ff80028771c14fecf2f37c1b14e46deec59c83d3b943c51d315bd3bf7d32c399ed0c4ce6003339ab9ed4ad168bfb595e43530c9d73ff02ab0f1263d93b
    const vectorsA112 = {
        seed: hexToBytes('a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'),
        skS: hexToBytes('caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1701'),
        input: hexToBytes('5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a'),
        info: hexToBytes('7465737420696e666f'),
        blind: hexToBytes('5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b'),
        blindedElement: hexToBytes('483d4f39de5ff77fa0f9a0ad2334dd5bf87f2cda868539d21de67ce49e7d1536'),
        evaluatedElement: hexToBytes('6eef6ee53c6fb17c77ae47e78bdca2e1094f98785e7b9a14f09be20797dad656'),
        output: hexToBytes(
            'b090b2ff80028771c14fecf2f37c1b14e46deec59c83d3b943c51d315bd3bf7d32c399ed0c4ce6003339ab9ed4ad168bfb595e43530c9d73ff02ab0f1263d93b'
        ),
    }

    type BaseBatchSize1Vector = typeof vectorsA111

    function baseServerContextBatchSize1Evaluate(v: BaseBatchSize1Vector) {
        const { info, blindedElement, seed } = v

        const vEvaluatedElement = v.evaluatedElement

        const { skS } = ciphersuite.GG.deriveKeyPair(seed)

        const serverContext = new ServerContextImpl(ciphersuite, skS)

        const evaluatedElement = serverContext.evaluate(blindedElement, info)
        expect(evaluatedElement).toEqual(vEvaluatedElement)
    }

    function baseClientContextFinalize(v: BaseBatchSize1Vector) {
        const { input, info, blind, evaluatedElement } = v
        const vOutput = v.output

        const clientContext = new ClientContextImpl(ciphersuite)

        const output = clientContext.finalize(input, blind, evaluatedElement, info)
        expect(output).toEqual(vOutput)
    }

    function baseModeFullProtocol(v: BaseBatchSize1Vector) {
        const { seed, input, info } = v

        const vOutput = v.output

        const { skS } = ciphersuite.GG.deriveKeyPair(seed)

        const clientContext = new ClientContextImpl(ciphersuite)
        const serverContext = new ServerContextImpl(ciphersuite, skS)

        const { blind, blindedElement } = clientContext.blind(input)

        const evaluatedElement = serverContext.evaluate(blindedElement, info)

        const output = clientContext.finalize(input, blind, evaluatedElement, info)
        expect(output).toEqual(vOutput)
    }

    function baseModeFullEvaluate(v: BaseBatchSize1Vector) {
        const { seed, input, info } = v

        const vOutput = v.output

        const { skS } = ciphersuite.GG.deriveKeyPair(seed)
        const serverContext = new ServerContextImpl(ciphersuite, skS)

        const output = serverContext.fullEvaluate(input, info)
        expect(output).toEqual(vOutput)
    }

    function baseModeVerifyFinalize(v: BaseBatchSize1Vector) {
        const { seed, input, info, output } = v
        const { skS } = ciphersuite.GG.deriveKeyPair(seed)
        const serverContext = new ServerContextImpl(ciphersuite, skS)

        const valid = serverContext.verifyFinalize(input, output, info)
        expect(valid).toBe(true)
    }

    test('A.1.1.1 Test Vector 1 Batch Size 1: ServerContext::evaluate', () => {
        baseServerContextBatchSize1Evaluate(vectorsA111)
    })

    test('A.1.1.1 Test Vector 1 Batch Size 1: ClientContext::finalize', () => {
        baseClientContextFinalize(vectorsA111)
    })

    test('A.1.1.1 Test Vector 1 Batch Size 1: Full run with random blind', () => {
        baseModeFullProtocol(vectorsA111)
    })

    test('A.1.1.1 Test Vector 1 Batch Size 1: ServerContext::FullEvaluate', () => {
        baseModeFullEvaluate(vectorsA111)
    })

    test('A.1.1.1 Test Vector 1 Batch Size 1: ServerContext::VerifyFinalize', () => {
        baseModeVerifyFinalize(vectorsA111)
    })

    test('A.1.1.2 Test Vector 2 Batch Size 1: ServerContext::evaluate', () => {
        baseServerContextBatchSize1Evaluate(vectorsA112)
    })

    test('A.1.1.2 Test Vector 2 Batch Size 1: ClientContext::finalize', () => {
        baseClientContextFinalize(vectorsA112)
    })

    test('A.1.1.2 Test Vector 2 Batch Size 1: Full run with random blind', () => {
        baseModeFullProtocol(vectorsA112)
    })

    test('A.1.1.2 Test Vector 2 Batch Size 1: ServerContext::FullEvaluate', () => {
        baseModeFullEvaluate(vectorsA112)
    })

    test('A.1.1.2 Test Vector 2 Batch Size 1: ServerContext::VerifyFinalize', () => {
        baseModeVerifyFinalize(vectorsA112)
    })
})
