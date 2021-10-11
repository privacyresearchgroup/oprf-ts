// (c) 2021 Privacy Research, LLC https://privacyresearch.io,  GPL-v3-only: see LICENSE file.

import { contextString, I2OSP, makeDST, OPRFMode } from '../specification-utils'
import { Ciphersuite, Opaque, PrivateInput, PublicInput, SerializedElement, SerializedScalar } from '../types'

export interface ClientContext {
    blind(input: PrivateInput): { blind: SerializedScalar; blindedElement: SerializedElement }
    unblind(blind: SerializedScalar, evaluatedElement: SerializedElement): SerializedElement
    finalize(
        input: PrivateInput,
        blind: SerializedScalar,
        evaluatedElement: SerializedElement,
        info: PublicInput
    ): Opaque
}

export class ClientContextImpl<PointType, IntType, ScalarType = IntType> implements ClientContext {
    public readonly contextString: Uint8Array
    constructor(protected _ciphersuite: Ciphersuite<PointType, IntType, ScalarType>) {
        this.contextString = contextString(OPRFMode.Base, _ciphersuite.ID)
    }
    blind(
        input: PrivateInput,
        randScalar?: SerializedScalar
    ): { blind: SerializedScalar; blindedElement: SerializedElement } {
        const { GG } = this._ciphersuite
        const blind = (randScalar && GG.deserializeScalar(randScalar)) || GG.randomScalar()
        const P = GG.hashToGroup(input)
        const blindedElement = GG.serializeElement(GG.scalarMultiply(P, blind))
        return { blind: GG.serializeScalar(blind), blindedElement }
    }

    unblind(blind: SerializedScalar, evaluatedElement: SerializedElement): SerializedElement {
        const { GG } = this._ciphersuite
        const Z = GG.deserializeElement(evaluatedElement)
        const blindInverse = GG.invertScalar(GG.deserializeScalar(blind))
        const N = GG.scalarMultiply(Z, blindInverse)

        return GG.serializeElement(N)
    }
    finalize(
        input: PrivateInput,
        blind: SerializedScalar,
        evaluatedElement: SerializedElement,
        info: PublicInput
    ): Opaque {
        const unblindedElement = this.unblind(blind, evaluatedElement)
        const finalizeDST = makeDST('Finalize-', this.contextString)
        const hashInput = Uint8Array.from([
            ...I2OSP(input.length, 2),
            ...input,
            ...I2OSP(info.length, 2),
            ...info,
            ...I2OSP(unblindedElement.length, 2),
            ...unblindedElement,
            ...I2OSP(finalizeDST.length, 2),
            ...finalizeDST,
        ])
        return this._ciphersuite.hash(hashInput)
    }
}
