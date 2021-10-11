// (c) 2021 Privacy Research, LLC https://privacyresearch.io,  GPL-v3-only: see LICENSE file.

import { contextString, I2OSP, latin1ToBytes, makeDST, OPRFMode } from '../specification-utils'
import { Ciphersuite, PublicInput, SerializedElement, SerializedScalar } from '../types'
import { ServerContextImpl } from './base-server-context'

export interface VerifiableServerContext {
    verifiableEvaluate(
        blindedElement: SerializedElement,
        info: PublicInput
    ): { evaluatedElement: SerializedElement; proof: Proof }
}
export interface Proof {
    c: SerializedScalar
    s: SerializedScalar
}

export class VerifiableServerContextImpl<PointType, IntType, ScalarType = IntType>
    extends ServerContextImpl<PointType, IntType, ScalarType>
    implements VerifiableServerContext
{
    public readonly contextString: Uint8Array
    public readonly pkS: PointType
    constructor(_ciphersuite: Ciphersuite<PointType, IntType, ScalarType>, _skS: ScalarType) {
        super(_ciphersuite, _skS)
        const { GG } = _ciphersuite
        this.contextString = contextString(OPRFMode.Verified, _ciphersuite.ID)
        this.pkS = GG.scalarMultiply(GG.G, _skS)
    }

    verifiableEvaluate(
        blindedElement: SerializedElement,
        info: Uint8Array,
        randScalar?: SerializedScalar
    ): { evaluatedElement: SerializedElement; proof: Proof } {
        const { evaluatedElements, proof } = this.verifiableEvaluateBatch([blindedElement], info, randScalar)
        return { evaluatedElement: evaluatedElements[0], proof }
    }
    verifiableEvaluateBatch(
        blindedElements: SerializedElement[],
        info: Uint8Array,
        randScalar?: SerializedScalar
    ): { evaluatedElements: SerializedElement[]; proof: Proof } {
        const { GG } = this._ciphersuite
        const context = Uint8Array.from([
            ...latin1ToBytes('Context-'),
            ...this.contextString,
            ...I2OSP(info.length, 2),
            ...info,
        ])
        const m = GG.hashToScalar(context)
        const t = GG.addScalars(this._skS, m)

        const Rs = blindedElements.map((blindedElement) => GG.deserializeElement(blindedElement))
        const Zs = Rs.map((R) => GG.scalarMultiply(R, GG.invertScalar(t)))
        const evaluatedElements = Zs.map((Z) => GG.serializeElement(Z))

        const U = GG.scalarMultiply(GG.G, t)
        const proof = this.generateProof(t, GG.G, U, Zs, Rs, randScalar)
        return { evaluatedElements, proof }
    }
    private generateProof(
        k: ScalarType,
        A: PointType,
        B: PointType,
        Cs: PointType[],
        Ds: PointType[],
        randScalar?: SerializedScalar
    ): Proof {
        const { GG } = this._ciphersuite
        const [M, Z] = this.computeCompositesFast(k, B, Cs, Ds)

        const r = randScalar ? GG.deserializeScalar(randScalar) : GG.randomScalar()

        const t2 = GG.scalarMultiply(A, r)
        const t3 = GG.scalarMultiply(M, r)

        const Bm = GG.serializeElement(B)
        const a0 = GG.serializeElement(M)
        const a1 = GG.serializeElement(Z)
        const a2 = GG.serializeElement(t2)
        const a3 = GG.serializeElement(t3)

        const challengeDST = makeDST('Challenge-', this.contextString)
        const h2Input = Uint8Array.from([
            ...I2OSP(Bm.length, 2),
            ...Bm,
            ...I2OSP(a0.length, 2),
            ...a0,
            ...I2OSP(a1.length, 2),
            ...a1,
            ...I2OSP(a2.length, 2),
            ...a2,
            ...I2OSP(a3.length, 2),
            ...a3,
            ...I2OSP(challengeDST.length, 2),
            ...challengeDST,
        ])
        const c = GG.hashToScalar(h2Input)
        const s = GG.subtractScalars(r, GG.multiplyScalars(c, k))

        return { c: GG.serializeScalar(c), s: GG.serializeScalar(s) }
    }

    private computeCompositesFast(k: ScalarType, B: PointType, Cs: PointType[], Ds: PointType[]): PointType[] {
        const { GG, hash } = this._ciphersuite
        if (Cs.length !== Ds.length) {
            throw new Error('Invalid arguments.')
        }
        const m = Cs.length

        const Bm = GG.serializeElement(B)
        const seedDST = makeDST('Seed-', this.contextString)
        const compositeDST = makeDST('Composite-', this.contextString)
        const h1Input = Uint8Array.from([...I2OSP(Bm.length, 2), ...Bm, ...I2OSP(seedDST.length, 2), ...seedDST])
        const seed = hash(h1Input)

        let M = GG.identity()
        for (let i = 0; i < m; ++i) {
            const Ci = GG.serializeElement(Cs[i])
            const Di = GG.serializeElement(Ds[i])
            const h2Input = Uint8Array.from([
                ...I2OSP(seed.length, 2),
                ...seed,
                ...I2OSP(i, 2),
                ...I2OSP(Ci.length, 2),
                ...Ci,
                ...I2OSP(Di.length, 2),
                ...Di,
                ...I2OSP(compositeDST.length, 2),
                ...compositeDST,
            ])

            const di = GG.hashToScalar(h2Input)
            M = GG.add(GG.scalarMultiply(Cs[i], di), M)
        }
        const Z = GG.scalarMultiply(M, k)
        return [M, Z]
    }
}
