// (c) 2021 Privacy Research, LLC https://privacyresearch.io,  GPL-v3-only: see LICENSE file.
import crypto from 'crypto'
import { expand_message_xmd } from '../ristretto255-sha512/hash'
import {
    contextString,
    CT_EQUAL,
    I2OSP,
    latin1ToBytes,
    makeDST,
    Nh,
    numberArrayXOR,
    OPRFCiphersuite,
    OPRFMode,
    OS2IP,
    SPEC_ID,
} from '../specification-utils'
import { performance } from 'perf_hooks'

describe('Test specification utilities', () => {
    test('string-binary conversion', () => {
        const shouldBeSpecID = latin1ToBytes('VOPRF07-')
        expect(shouldBeSpecID).toEqual(SPEC_ID)
    })

    test('Context strings', () => {
        const BASE_MODE_CONTEXT_STRING = Uint8Array.from([86, 79, 80, 82, 70, 48, 55, 45, 0, 0, 1])
        const VERIFY_MODE_CONTEXT_STRING = Uint8Array.from([86, 79, 80, 82, 70, 48, 55, 45, 1, 0, 1])

        expect(contextString(OPRFMode.Base, OPRFCiphersuite.Ristretto255SHA512)).toEqual(BASE_MODE_CONTEXT_STRING)
        expect(contextString(OPRFMode.Verified, OPRFCiphersuite.Ristretto255SHA512)).toEqual(VERIFY_MODE_CONTEXT_STRING)
    })

    test('PKCS1 integer-octet string conversion', () => {
        const xi = 129 * 256 ** 5 + 128 * 256 ** 4 + 127 * 256 ** 3 + 126 * 256 ** 2 + 125 * 256 ** 1 + 124
        const xos6 = I2OSP(xi, 6)
        const xos8 = I2OSP(xi, 8)

        expect(xos6).toEqual(Uint8Array.from([129, 128, 127, 126, 125, 124]))
        expect(xos8).toEqual(Uint8Array.from([0, 0, 129, 128, 127, 126, 125, 124]))

        expect(() => {
            I2OSP(xi, 5)
        }).toThrow('Integer to large for 5 byte array.')

        expect(OS2IP(xos6)).toEqual(xi)
        expect(OS2IP(xos8)).toEqual(xi)
    })

    test('CT_EQUAL', () => {
        const equalPrefixLengths = [0, 16, 256, 4096, 8191]
        const arrayLength = 8192
        const baseArray = Uint8Array.from(crypto.randomBytes(arrayLength))
        expect(CT_EQUAL(baseArray, baseArray)).toBe(true)

        const numTests = 10000
        const results: Record<number | string, number[]> = {
            [0]: [],
            [16]: [],
            [256]: [],
            [4096]: [],
            [8191]: [],
            total: [],
        }
        for (let i = 0; i < numTests; ++i) {
            const suffixes = equalPrefixLengths.map((n) => Uint8Array.from(crypto.randomBytes(arrayLength - n)))
            for (const suffix of suffixes) {
                const testArray = Uint8Array.from([...baseArray.slice(0, arrayLength - suffix.length), ...suffix])
                const other = Uint8Array.from(baseArray)
                // make sure the arrays are different at least in the last byte
                testArray[testArray.length - 1] = 255 - baseArray[testArray.length - 1]
                const t1 = performance.now()
                const shouldBeFalse = CT_EQUAL(testArray, other)
                const t2 = performance.now()
                const duration = t2 - t1
                results.total.push(duration)
                results[arrayLength - suffix.length].push(duration)
                if (shouldBeFalse) {
                    console.log({ i, suffix })
                }
                expect(shouldBeFalse).toBe(false)
            }
        }

        // now do analysis
        const totalStats = arrayStatistics(results.total)
        for (const key of Object.keys(results)) {
            const stats = arrayStatistics(results[key])
            console.log({
                key,
                stats,
                propVar: ((stats.mean - totalStats.mean) * Math.sqrt(numTests)) / stats.stddev,
            })
            expect((Math.abs(totalStats.mean - stats.mean) * Math.sqrt(numTests)) / stats.stddev).toBeLessThan(10)
        }
    })
    test('CT_EQUAL bad input', () => {
        expect(() => {
            CT_EQUAL(Uint8Array.from([1, 2, 3]), Uint8Array.from([1]))
        }).toThrow()
    })

    test('numberArrayXOR', () => {
        const xor = numberArrayXOR([127, 255, 8], [8, 24, 8])
        expect(xor).toEqual(Uint8Array.from([119, 231, 0]))
    })

    test('numberArrayXOR bad input', () => {
        expect(() => {
            numberArrayXOR(Uint8Array.from([1, 2, 3]), Uint8Array.from([1]))
        }).toThrow()
    })

    test('Reject expansion when too big', () => {
        const dst = makeDST('ExpansionTest-', contextString(OPRFMode.Base, OPRFCiphersuite.Ristretto255SHA512))
        expect(() => {
            expand_message_xmd(Uint8Array.from([0, 0, 0]), dst, 255 * Nh[OPRFCiphersuite.Ristretto255SHA512] + 1)
        }).toThrow('Requested expanded length too large.')
    })

    test('Large expansion', () => {
        const dst = makeDST('ExpansionTest-', contextString(OPRFMode.Base, OPRFCiphersuite.Ristretto255SHA512))
        expect(() => {
            expand_message_xmd(Uint8Array.from([0, 0, 0]), dst, 255 * Nh[OPRFCiphersuite.Ristretto255SHA512])
        }).not.toThrow('Requested expanded length too large.')
    })
})

function arrayStatistics(arr: number[]) {
    let sum = 0
    let sumSquares = 0
    let max = Number.MIN_VALUE
    let min = Number.MAX_VALUE
    for (const n of arr) {
        sum += n
        sumSquares += n * n
        max = Math.max(n, max)
        min = Math.min(n, min)
    }
    const mean = sum / arr.length
    const variance = sumSquares / arr.length - mean * mean
    return {
        mean,
        variance,
        min,
        max,
        stddev: Math.sqrt(variance),
    }
}
