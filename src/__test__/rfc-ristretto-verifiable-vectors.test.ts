import { makeED } from '@privacyresearch/ed25519-ts'
import { hexToBytes } from '@privacyresearch/ed25519-ts/lib/serialization'
import JSBI from 'jsbi'
import { VerifiableClientContextImpl } from '../contexts/verifiable-client-context'
import { VerifiableServerContextImpl } from '../contexts/verifiable-server-context'
import { ristretto255SHA512Ciphersuite } from '../ristretto255-sha512/ciphersuite'
import { numberArrayXOR, OPRFMode } from '../specification-utils'

const ed = makeED(JSBI)
const ciphersuite = ristretto255SHA512Ciphersuite<JSBI>(ed, OPRFMode.Verified)

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

    // Input = 00
    // Info = 7465737420696e666f
    // Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e3263503
    // BlindedElement = 3a0a53f2c57e5ee0d89e394087f8e5f95b24159db01c31933a07f0e6414c954d
    // EvaluationElement = f8a50ed35a477b0cde91d926e1bc5ae59b97d5bd0dda51a728b0f036ec557d79
    // Proof = 7a5375eb1dbad259431f5c294e816a1c1483c279748da1a75d91f8a81438ea08355d4087d4d848b46878dcc8fb5849ac7a09133382c2c6129564a7f7b4b7bf01
    // ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9dbcec831b8c681a09
    // Output = 4b2ff4c984985829c3cd9d90c255cdc0d6b61c4c0aafa9215769d51cf7deb01472ba945928a8305e010f12b7dcc75a9dc2460439e6297d57dc2ce7ca0abaae1a
    const vectorsA121 = {
        seed: hexToBytes('a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'),
        skS: hexToBytes('ac37d5850510299406ea8eb8fa226a7bfc2467a4b070d6c7bf667948b9600b00'),
        pkS: hexToBytes('0c0254e22063cae3e1bae02fb6fa20882664a117c0278eda6bda3372c0dd9860'),
        input: hexToBytes('00'),
        info: hexToBytes('7465737420696e666f'),
        blind: hexToBytes('ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e3263503'),
        blindedElement: hexToBytes('3a0a53f2c57e5ee0d89e394087f8e5f95b24159db01c31933a07f0e6414c954d'),
        evaluatedElement: hexToBytes('f8a50ed35a477b0cde91d926e1bc5ae59b97d5bd0dda51a728b0f036ec557d79'),
        proof: hexToBytes(
            '7a5375eb1dbad259431f5c294e816a1c1483c279748da1a75d91f8a81438ea08355d4087d4d848b46878dcc8fb5849ac7a09133382c2c6129564a7f7b4b7bf01'
        ),
        proofRandomScalar: hexToBytes('019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9dbcec831b8c681a09'),
        output: hexToBytes(
            '4b2ff4c984985829c3cd9d90c255cdc0d6b61c4c0aafa9215769d51cf7deb01472ba945928a8305e010f12b7dcc75a9dc2460439e6297d57dc2ce7ca0abaae1a'
        ),
    }
    // Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
    // Info = 7465737420696e666f
    // Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171ea02
    // BlindedElement = a86dd4544d0f3ea973926054230767dff16016215f2d73f26d3f86a81f38cf1a
    // EvaluationElement = 9e47810f1de1b57ebe163a95c170ec165a2063f872155c376d94e8de2157af70
    // Proof = 61075125d851d5164b0aa1a4d5ddeebaf097266450ac6019579af5f7abd190088eb0f6f1e7f9d8bfddbc21ae3c25a065e6c4e797d15f345ed4fb9ee468d24c0a
    // ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df9d013f7d6c312a0b
    //                     74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df9d013f7d6c312a0b
    // Output = fe1fb7fa49c37dc7cd31d64859b4a2e6ae0cef294f2764e6f12f7d809f218047d1fde147cf69807b8971fb2c316eb572be2b5bf491813bfec0a20668d6d07b0b
    const vectorsA122 = {
        seed: hexToBytes('a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'),
        skS: hexToBytes('ac37d5850510299406ea8eb8fa226a7bfc2467a4b070d6c7bf667948b9600b00'),
        pkS: hexToBytes('0c0254e22063cae3e1bae02fb6fa20882664a117c0278eda6bda3372c0dd9860'),
        input: hexToBytes('5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a'),
        info: hexToBytes('7465737420696e666f'),
        blind: hexToBytes('e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171ea02'),
        blindedElement: hexToBytes('a86dd4544d0f3ea973926054230767dff16016215f2d73f26d3f86a81f38cf1a'),
        evaluatedElement: hexToBytes('9e47810f1de1b57ebe163a95c170ec165a2063f872155c376d94e8de2157af70'),
        proof: hexToBytes(
            '61075125d851d5164b0aa1a4d5ddeebaf097266450ac6019579af5f7abd190088eb0f6f1e7f9d8bfddbc21ae3c25a065e6c4e797d15f345ed4fb9ee468d24c0a'
        ),
        proofRandomScalar: hexToBytes('74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df9d013f7d6c312a0b'),
        output: hexToBytes(
            'fe1fb7fa49c37dc7cd31d64859b4a2e6ae0cef294f2764e6f12f7d809f218047d1fde147cf69807b8971fb2c316eb572be2b5bf491813bfec0a20668d6d07b0b'
        ),
    }

    type VerifiableBatchSize1Vector = typeof vectorsA121

    function verifiableServerContextBatchSize1Evaluate(v: VerifiableBatchSize1Vector) {
        const { info, blindedElement, seed } = v

        const vEvaluatedElement = v.evaluatedElement

        const { skS } = ciphersuite.GG.deriveKeyPair(seed)

        const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

        const evaluatedElement = serverContext.evaluate(blindedElement, info)
        expect(evaluatedElement).toEqual(vEvaluatedElement)
    }

    function verifiableClientContextFinalize(v: VerifiableBatchSize1Vector) {
        const { input, info, blind, evaluatedElement } = v
        const vOutput = v.output

        const pkS = ciphersuite.GG.deserializeElement(v.pkS)

        const clientContext = new VerifiableClientContextImpl(ciphersuite, pkS)

        const output = clientContext.finalize(input, blind, evaluatedElement, info)
        expect(output).toEqual(vOutput)
    }

    function verifiableModeFullProtocol(v: VerifiableBatchSize1Vector) {
        const { seed, input, info } = v

        const vOutput = v.output

        const { skS, pkS } = ciphersuite.GG.deriveKeyPair(seed)

        const clientContext = new VerifiableClientContextImpl(ciphersuite, pkS)
        const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

        const { blind, blindedElement } = clientContext.blind(input)

        const { evaluatedElement, proof } = serverContext.verifiableEvaluate(blindedElement, info)

        const output = clientContext.verifiableFinalize(input, blind, evaluatedElement, blindedElement, proof, info)
        expect(output).toEqual(vOutput)
    }

    function verifiableModeFullEvaluate(v: VerifiableBatchSize1Vector) {
        const { seed, input, info } = v

        const vOutput = v.output

        const { skS } = ciphersuite.GG.deriveKeyPair(seed)
        const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

        const output = serverContext.fullEvaluate(input, info)
        expect(output).toEqual(vOutput)
    }

    function verifiableModeVerifyFinalize(v: VerifiableBatchSize1Vector) {
        const { seed, input, info, output } = v
        const { skS } = ciphersuite.GG.deriveKeyPair(seed)
        const serverContext = new VerifiableServerContextImpl(ciphersuite, skS)

        const valid = serverContext.verifyFinalize(input, output, info)
        expect(valid).toBe(true)
    }

    function verifiableClientContextAcceptProof(v: VerifiableBatchSize1Vector) {
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
            clientContext.verifiableFinalize(input, blind, evaluatedElement, blindedElement, proof, info)
        }).not.toThrow()
        expect(() => {
            clientContext.verifiableFinalize(input, blind, evaluatedElement, blindedElement, badProof, info)
        }).toThrow()
        expect(() => {
            badPKClientContext.verifiableFinalize(input, blind, evaluatedElement, blindedElement, badProof, info)
        }).toThrow()
    }

    function generateProof(v: VerifiableBatchSize1Vector) {
        const { GG } = ciphersuite
        const { seed, info, proofRandomScalar } = v

        expect(v.proof.length).toEqual(64)
        const vProof = { c: v.proof.slice(0, 32), s: v.proof.slice(32, 64) }

        const { skS } = GG.deriveKeyPair(seed)

        const server = new VerifiableServerContextImpl(ciphersuite, skS)

        const { evaluatedElement, proof } = server.verifiableEvaluate(v.blindedElement, info, proofRandomScalar)
        expect(evaluatedElement).toEqual(v.evaluatedElement)

        expect(vProof.c).toEqual(proof.c)
        expect(vProof.s).toEqual(proof.s)
    }

    test('A.1.2.1 Test Vector 1 Batch Size 1: VerifiableServerContext::evaluate', () => {
        verifiableServerContextBatchSize1Evaluate(vectorsA121)
    })

    test('A.1.2.1 Test Vector 1 Batch Size 1: ClientContext::finalize', () => {
        verifiableClientContextFinalize(vectorsA121)
    })

    test('A.1.2.1 Test Vector 1 Batch Size 1: Full run with random blind', () => {
        verifiableModeFullProtocol(vectorsA121)
    })

    test('A.1.2.1 Test Vector 1 Batch Size 1: VerifiableServerContext::FullEvaluate', () => {
        verifiableModeFullEvaluate(vectorsA121)
    })

    test('A.1.2.1 Test Vector 1 Batch Size 1: VerifiableServerContext::VerifyFinalize', () => {
        verifiableModeVerifyFinalize(vectorsA121)
    })

    test('A.1.2.1 Test Vector 1 Batch Size 1: Test verification', () => {
        verifiableClientContextAcceptProof(vectorsA121)
    })

    test('A.1.2.2 Test Vector 2 Batch Size 1: ServerVerifiableServerContextContext::evaluate', () => {
        verifiableServerContextBatchSize1Evaluate(vectorsA122)
    })

    test('A.1.2.2 Test Vector 2 Batch Size 1: ClientContext::finalize', () => {
        verifiableClientContextFinalize(vectorsA122)
    })

    test('A.1.2.2 Test Vector 2 Batch Size 1: Full run with random blind', () => {
        verifiableModeFullProtocol(vectorsA122)
    })

    test('A.1.2.2 Test Vector 2 Batch Size 1: VerifiableServerContext::FullEvaluate', () => {
        verifiableModeFullEvaluate(vectorsA122)
    })

    test('A.1.2.2 Test Vector 2 Batch Size 1: VerifiableServerContext::VerifyFinalize', () => {
        verifiableModeVerifyFinalize(vectorsA122)
    })

    test('A.1.2.2 Test Vector 2 Batch Size 1: Test verification', () => {
        verifiableClientContextAcceptProof(vectorsA122)
    })
    test('A.1.2.2 Test Vector 2 Batch Size 1: generate proof', () => {
        generateProof(vectorsA122)
    })
})
