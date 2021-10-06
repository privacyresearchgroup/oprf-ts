import { I2OSP, Nh, OPRFCiphersuite } from '../specification-utils'
import * as hash from 'hash.js'

function numberArrayXOR(a1: number[] | Uint8Array, a2: number[] | Uint8Array): Uint8Array {
    if (a1.length !== a2.length) {
        throw new Error('Byte arrays must be same size to XOR.')
    }
    const result = new Uint8Array(a1.length)
    for (const i in a1) {
        result[i] = a1[i] ^ a2[i]
    }
    return result
}

// TODO: abbstract this so it is implemented once for all siphersuites that use it
// Specified at https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.1
export function expand_message_xmd(
    msg: Uint8Array,
    DST: Uint8Array,
    lenInBytes = Nh[OPRFCiphersuite.Ristretto255SHA512]
): Uint8Array {
    const sInBytes = 128 // Input hash size for SHA512, 1024 bits
    const ell = Math.ceil(lenInBytes / Nh[OPRFCiphersuite.Ristretto255SHA512])
    if (ell > 255) {
        throw new Error('Requested expanded length too large.')
    }
    const DSTprime = [...DST, ...I2OSP(DST.length, 1)]
    const Zpad = I2OSP(0, sInBytes)
    const libStr = I2OSP(lenInBytes, 2)
    const msgprime = [...Zpad, ...msg, ...libStr, ...I2OSP(0, 1), ...DSTprime]

    const b0 = hash.sha512().update(msgprime).digest()
    const b1 = hash
        .sha512()
        .update([...b0, ...I2OSP(1, 1), ...DSTprime])
        .digest()
    const bs = new Array<Array<number>>(ell + 1)
    bs[0] = b0
    bs[1] = b1
    for (let i = 2; i <= ell; ++i) {
        bs[i] = hash
            .sha512()
            .update([...numberArrayXOR(bs[0], bs[i - 1]), ...I2OSP(i, 1), ...DSTprime])
            .digest()
    }

    const uniformBytes = bs.slice(1).reduce((acc, curr) => acc.concat(curr), [])
    return Uint8Array.from(uniformBytes.slice(0, lenInBytes))
}

export function ciphersuiteHash(input: Uint8Array): Uint8Array {
    return Uint8Array.from(hash.sha512().update(input).digest())
}
