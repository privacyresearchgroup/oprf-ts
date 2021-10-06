import { makeED } from '@privacyresearch/ed25519-ts'
import { hexToBytes } from '@privacyresearch/ed25519-ts/lib/serialization'
import JSBI from 'jsbi'
import { ristretto255SHA512Ciphersuite } from '../ristretto255-sha512/ciphersuite'
import { OPRFMode } from '../specification-utils'

const ed = makeED(JSBI)
const ciphersuite = ristretto255SHA512Ciphersuite<JSBI>(ed, OPRFMode.Base)

describe('Ristretto RFC tests', () => {
    test('test key derivation', () => {
        const seed = hexToBytes('a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3')
        const skSm = hexToBytes('caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1701')

        expect(seed.length).toEqual(32)
        const { skS } = ciphersuite.GG.deriveKeyPair(seed)
        const skSBytes = ciphersuite.GG.serializeScalar(skS)
        expect(skSBytes.length).toEqual(32)

        expect(skSBytes).toEqual(skSm)
    })
})
