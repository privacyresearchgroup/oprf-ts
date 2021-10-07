import { contextString, CT_EQUAL, I2OSP, latin1ToBytes, makeDST, OPRFMode } from '../specification-utils'
import { Ciphersuite, Opaque, PrivateInput, PublicInput, SerializedElement, SerializedScalar } from '../types'
import { ClientContext, ClientContextImpl } from './base-client-context'
import { Proof } from './verifiable-server-context'

export interface VerifiableClientContext extends ClientContext {
    verifiableUnblind(
        blind: SerializedScalar,
        evaluatedElement: SerializedElement,
        blindedElement: SerializedElement,
        proof: Proof,
        info: PublicInput
    ): SerializedElement
    verifiableFinalize(
        input: PrivateInput,
        blind: SerializedScalar,
        evaluatedElement: SerializedElement,
        blindedElement: SerializedElement,
        proof: Proof,
        info: PublicInput
    ): Opaque
}

export class VerifiableClientContextImpl<PointType, IntType, ScalarType = IntType>
    extends ClientContextImpl<PointType, IntType, ScalarType>
    implements VerifiableClientContext
{
    public readonly contextString: Uint8Array
    constructor(_ciphersuite: Ciphersuite<PointType, IntType, ScalarType>, protected _pkS: PointType) {
        super(_ciphersuite)
        this.contextString = contextString(OPRFMode.Verified, _ciphersuite.ID)
    }
    verifiableUnblind(
        blind: SerializedScalar,
        evaluatedElement: SerializedElement,
        blindedElement: SerializedElement,
        proof: Proof,
        info: PublicInput
    ): SerializedElement {
        const { GG } = this._ciphersuite

        const context = Uint8Array.from([
            ...latin1ToBytes('Context-'),
            ...this.contextString,
            ...I2OSP(info.length, 2),
            ...info,
        ])
        const m = GG.hashToScalar(context)

        const R = GG.deserializeElement(blindedElement)
        const Z = GG.deserializeElement(evaluatedElement)

        const T = GG.scalarMultiply(GG.G, m)
        const U = GG.add(T, this._pkS)

        if (!this.verifyProof(GG.G, U, Z, R, proof)) {
            throw new Error('Verification Error')
        }

        const blindInverse = GG.invertScalar(GG.deserializeScalar(blind))
        const N = GG.scalarMultiply(Z, blindInverse)
        return GG.serializeElement(N)
    }

    verifyProof(A: PointType, B: PointType, C: PointType, D: PointType, proof: Proof): boolean {
        const { GG } = this._ciphersuite
        const Cs = [C]
        const Ds = [D]

        const [M, Z] = this.computeComposites(B, Cs, Ds)
        const c = GG.deserializeScalar(proof.c)
        const s = GG.deserializeScalar(proof.s)

        const t2 = GG.add(GG.scalarMultiply(A, s), GG.scalarMultiply(B, c))
        const t3 = GG.add(GG.scalarMultiply(M, s), GG.scalarMultiply(Z, c))
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
        const expectedC = GG.serializeScalar(GG.hashToScalar(h2Input))
        // console.log('verifyProof', { expectedC, c: proof.c })
        return CT_EQUAL(expectedC, proof.c)
    }

    private computeComposites(B: PointType, Cs: PointType[], Ds: PointType[]): PointType[] {
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
        let Z = GG.identity()
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
            Z = GG.add(GG.scalarMultiply(Ds[i], di), Z)
        }
        return [M, Z]
    }

    verifiableFinalize(
        input: PrivateInput,
        blind: SerializedScalar,
        evaluatedElement: SerializedElement,
        blindedElement: SerializedElement,
        proof: Proof,
        info: PublicInput
    ): Opaque {
        const unblindedElement = this.verifiableUnblind(blind, evaluatedElement, blindedElement, proof, info)
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
