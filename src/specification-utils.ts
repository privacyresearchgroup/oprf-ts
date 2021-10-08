export const SPEC_ID = Uint8Array.from([86, 79, 80, 82, 70, 48, 55, 45]) // "VOPRF07-"

export enum OPRFMode {
    Base = 0,
    Verified = 1,
}

export enum OPRFCiphersuite {
    Ristretto255SHA512 = 0x0001,
    Decaf448SHAKE256 = 0x0002,
    P256SHA256 = 0x0003,
    P384SHA384 = 0x0004,
    P521SHA512 = 0x0005,
}

export const Nh = {
    [OPRFCiphersuite.Ristretto255SHA512]: 64,
    [OPRFCiphersuite.Decaf448SHAKE256]: 64,
    [OPRFCiphersuite.P256SHA256]: 32,
    [OPRFCiphersuite.P384SHA384]: 48,
    [OPRFCiphersuite.P521SHA512]: 64,
}

export function latin1ToBytes(s: string): Uint8Array {
    return Uint8Array.from(s.split('').map((s) => s.charCodeAt(0)))
}

export function I2OSP(i: number, len: number): Uint8Array {
    if (i >= 256 ** len) {
        throw new Error(`Integer to large for ${len} byte array.`)
    }
    const octets = new Uint8Array(len)
    for (const index in octets) {
        octets[index] = Number(i % 256)
        i = i / 256
    }

    return octets.reverse()
}
export function OS2IP(os: Uint8Array): number {
    return Buffer.from(os)
        .reverse()
        .reduce((total, value, index) => (total += value * 256 ** index), 0)
}

export function contextString(mode: OPRFMode, cryptoSuiteId: number): Uint8Array {
    const osCSID = I2OSP(cryptoSuiteId, 2)
    return Uint8Array.from([...SPEC_ID, mode, ...osCSID])
}
export function CT_EQUAL(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        throw new Error('Cannot compare arrays of different lengths.')
    }
    let result = true
    for (const i in a) {
        result &&= a[i] === b[i]
    }
    return result
}

export function makeDST(prefixString: string, contextString: Uint8Array): Uint8Array {
    return Uint8Array.from([...latin1ToBytes(prefixString), ...contextString])
}

export function numberArrayXOR(a1: number[] | Uint8Array, a2: number[] | Uint8Array): Uint8Array {
    if (a1.length !== a2.length) {
        throw new Error('Byte arrays must be same size to XOR.')
    }
    const result = new Uint8Array(a1.length)
    for (const i in a1) {
        result[i] = a1[i] ^ a2[i]
    }
    return result
}
