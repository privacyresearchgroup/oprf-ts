import { contextString, CT_EQUAL, I2OSP, latin1ToBytes, makeDST, OPRFMode } from '../specification-utils'
import { Ciphersuite, Opaque, PrivateInput, PublicInput, SerializedElement, SerializedScalar } from '../types'

export interface ServerContext {
    evaluate(skS: SerializedScalar, blindedElement: SerializedElement, info: PublicInput): SerializedElement
    fullEvaluate(skS: SerializedScalar, input: PrivateInput, info: PublicInput): Opaque
    verifyFinalize(skS: SerializedScalar, input: PrivateInput, opaque: Opaque, info: PublicInput): boolean
}

export class ServerContextImpl<PointType, IntType, ScalarType = IntType> implements ServerContext {
    public readonly contextString: Uint8Array
    constructor(private _ciphersuite: Ciphersuite<PointType, IntType, ScalarType>, private _skS: ScalarType) {
        this.contextString = contextString(OPRFMode.Base, _ciphersuite.ID)
    }

    evaluate(skS: SerializedScalar, blindedElement: SerializedElement, info: Uint8Array): SerializedElement {
        const { GG } = this._ciphersuite
        const R = GG.deserializeElement(blindedElement)
        const context = Uint8Array.from([
            ...latin1ToBytes('Context-'),
            ...this.contextString,
            ...I2OSP(info.length, 2),
            ...info,
        ])
        const m = GG.hashToScalar(context)
        const t = GG.addScalars(GG.deserializeScalar(skS), m)
        const Z = GG.scalarMultiply(R, GG.invertScalar(t))
        return GG.serializeElement(Z)
    }
    fullEvaluate(skS: SerializedScalar, input: PrivateInput, info: PublicInput): Opaque {
        const { GG } = this._ciphersuite
        const P = GG.hashToGroup(input)
        const context = Uint8Array.from([
            ...latin1ToBytes('Context-'),
            ...this.contextString,
            ...I2OSP(info.length, 2),
            ...info,
        ])
        const m = GG.hashToScalar(context)
        const t = GG.addScalars(GG.deserializeScalar(skS), m)
        const T = GG.scalarMultiply(P, GG.invertScalar(t))
        const issuedElement = GG.serializeElement(T)
        const finalizeDST = makeDST('Finalize-', this.contextString)
        const hashInput = Uint8Array.from([
            ...I2OSP(input.length, 2),
            ...input,
            ...I2OSP(info.length, 2),
            ...info,
            ...I2OSP(issuedElement.length, 2),
            ...issuedElement,
            ...I2OSP(finalizeDST.length, 2),
            ...finalizeDST,
        ])
        return this._ciphersuite.hash(hashInput)
    }
    verifyFinalize(skS: SerializedScalar, input: PrivateInput, output: Opaque, info: PublicInput): boolean {
        const { GG, hash } = this._ciphersuite
        const T = GG.hashToGroup(input)
        const element = GG.serializeElement(T)
        const issuedElement = this.evaluate(skS, element, info)
        const finalizeDST = makeDST('Finalize-', this.contextString)
        const hashInput = Uint8Array.from([
            ...I2OSP(input.length, 2),
            ...input,
            ...I2OSP(info.length, 2),
            ...info,
            ...I2OSP(issuedElement.length, 2),
            ...issuedElement,
            ...I2OSP(finalizeDST.length, 2),
            ...finalizeDST,
        ])
        const digest = hash(hashInput)
        return CT_EQUAL(digest, output)
    }
}
