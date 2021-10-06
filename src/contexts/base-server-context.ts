import { contextString, I2OSP, latin1ToBytes, OPRFMode } from '../specification-utils'
import { Ciphersuite, PublicInput, SerializedElement, SerializedScalar } from '../types'

export interface ServerContext {
    evaluate(skS: SerializedScalar, blindedElement: SerializedElement, info: PublicInput): SerializedElement
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
}
