// (c) 2021 Privacy Research, LLC https://privacyresearch.io,  GPL-v3-only: see LICENSE file.

import { BigIntType, Ed25519Type, ExtendedPointBase } from '@privacyresearch/ed25519-ts'
import { OPRFCiphersuite, OPRFMode } from '../specification-utils'
import { Ciphersuite } from '../types'
import { Ristretto255Group } from './group'
import { ciphersuiteHash } from './hash'

export function ristretto255SHA512Ciphersuite<IntType extends BigIntType>(
    ed: Ed25519Type<IntType>,
    mode: OPRFMode
): Ciphersuite<ExtendedPointBase<IntType>, IntType> {
    return {
        GG: new Ristretto255Group<IntType>(ed, mode),
        ID: OPRFCiphersuite.Ristretto255SHA512,
        hash: ciphersuiteHash,
    }
}
