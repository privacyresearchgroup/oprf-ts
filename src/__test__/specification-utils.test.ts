// (c) 2021 Privacy Research, LLC https://privacyresearch.io,  GPL-v3-only: see LICENSE file.

import { expand_message_xmd } from '../ristretto255-sha512/hash'
import {
    contextString,
    I2OSP,
    latin1ToBytes,
    makeDST,
    Nh,
    OPRFCiphersuite,
    OPRFMode,
    OS2IP,
    SPEC_ID,
} from '../specification-utils'

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
