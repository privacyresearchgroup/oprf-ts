// (c) 2021 Privacy Research, LLC https://privacyresearch.io,  GPL-v3-only: see LICENSE file.

import { BigIntType, Ed25519Type, ExtendedPointBase } from '@privacyresearch/ed25519-ts'
import { contextString, makeDST, OPRFCiphersuite, OPRFMode } from '../specification-utils'
import { Group } from '../types'
import { expand_message_xmd } from './hash'

export class Ristretto255Group<IntType extends BigIntType> implements Group<ExtendedPointBase<IntType>, IntType> {
    private _contextString: Uint8Array
    constructor(private _ed: Ed25519Type<IntType>, private _verifyMode: OPRFMode) {
        this._contextString = contextString(_verifyMode, OPRFCiphersuite.Ristretto255SHA512) // _verifyMode ? VERIFY_MODE_CONTEXT_STRING : BASE_MODE_CONTEXT_STRING
    }
    // GroupOps
    add(A: ExtendedPointBase<IntType>, B: ExtendedPointBase<IntType>): ExtendedPointBase<IntType> {
        return A.add(B)
    }

    scalarMultiply(A: ExtendedPointBase<IntType>, s: IntType): ExtendedPointBase<IntType> {
        return A.multiply(s)
    }

    // ScalarOps
    invertScalar(a: IntType): IntType {
        return this._ed.math.mod(this._ed.math.invert(a, this._ed.CURVE.n), this._ed.CURVE.n)
    }
    addScalars(a: IntType, b: IntType): IntType {
        return this._ed.math.mod(this._ed.Ints.add(a, b), this._ed.CURVE.n)
    }
    subtractScalars(a: IntType, b: IntType): IntType {
        return this._ed.math.mod(this._ed.Ints.subtract(a, b), this._ed.CURVE.n)
    }
    multiplyScalars(a: IntType, b: IntType): IntType {
        return this._ed.math.mod(this._ed.Ints.multiply(a, b), this._ed.CURVE.n)
    }

    // GroupBase
    order(): IntType {
        return this._ed.CURVE.n
    }
    identity(): ExtendedPointBase<IntType> {
        return this._ed.ExtendedPoint.ZERO
    }
    get G(): ExtendedPointBase<IntType> {
        return this._ed.ExtendedPoint.BASE
    }

    hashToGroup(x: Uint8Array): ExtendedPointBase<IntType> {
        const DST = makeDST('HashToGroup-', this._contextString)
        const uniformBytes = expand_message_xmd(x, DST, 64)
        return this._ed.ExtendedPoint.fromRistrettoHash(uniformBytes)
    }
    hashToScalar(x: Uint8Array): IntType {
        const DST = makeDST('HashToScalar-', this._contextString)
        const uniformBytes = expand_message_xmd(x, DST, 64)
        return this._ed.math.mod(this._ed.scalars.deserializeNumber(uniformBytes), this._ed.CURVE.n)
    }
    randomScalar(): IntType {
        return this._ed.keyUtils.encodePrivate(this._ed.utils.randomPrivateKey())
    }
    serializeElement(A: ExtendedPointBase<IntType>): Uint8Array {
        return A.toRistrettoBytes()
    }
    deserializeElement(buf: Uint8Array): ExtendedPointBase<IntType> {
        return this._ed.ExtendedPoint.fromRistrettoBytes(buf)
    }
    serializeScalar(s: IntType): Uint8Array {
        return this._ed.scalars.serializeScalar(s)
    }
    deserializeScalar(buf: Uint8Array): IntType {
        return this._ed.scalars.deserializeScalar(buf)
    }
    deriveKeyPair(seed: Uint8Array): { skS: IntType; pkS: ExtendedPointBase<IntType> } {
        const skS = this.hashToScalar(seed)
        const pkS = this.G.multiply(skS)
        return { skS, pkS }
    }
}
