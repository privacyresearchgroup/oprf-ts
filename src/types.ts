// (c) 2021 Privacy Research, LLC https://privacyresearch.io,  GPL-v3-only: see LICENSE file.

import { OPRFCiphersuite } from './specification-utils'

export type SerializedElement = Uint8Array
export type SerializedScalar = Uint8Array
export type PrivateInput = Uint8Array
export type PublicInput = Uint8Array
export type Opaque = Uint8Array

// Operations specified in the RFC https://cfrg.github.io/draft-irtf-cfrg-voprf/draft-irtf-cfrg-voprf.html#name-prime-order-group-dependenc
export interface GroupBase<PointType, IntType, ScalarType = IntType> {
    order(): IntType
    identity(): PointType
    readonly G: PointType

    hashToGroup(x: Uint8Array): PointType
    hashToScalar(x: Uint8Array): ScalarType

    randomScalar(): ScalarType

    serializeElement(A: PointType): SerializedElement
    deserializeElement(buf: SerializedElement): PointType
    serializeScalar(s: ScalarType): SerializedElement
    deserializeScalar(buf: SerializedScalar): ScalarType

    // Not explicitly required in specification, but defined there.
    deriveKeyPair(seed: Uint8Array): { skS: IntType; pkS: PointType }
}

export interface GroupOps<PointType, ScalarType> {
    add(A: PointType, B: PointType): PointType
    scalarMultiply(A: PointType, s: ScalarType): PointType
}

export interface ScalarOps<ScalarType> {
    addScalars(a: ScalarType, b: ScalarType): ScalarType
    subtractScalars(a: ScalarType, b: ScalarType): ScalarType
    multiplyScalars(a: ScalarType, b: ScalarType): ScalarType
    invertScalar(a: ScalarType): ScalarType
}

export type Group<PointType, IntType, ScalarType = IntType> = GroupBase<PointType, IntType, ScalarType> &
    GroupOps<PointType, ScalarType> &
    ScalarOps<ScalarType>

export interface Ciphersuite<PointType, IntType, ScalarType = IntType> {
    GG: Group<PointType, IntType, ScalarType>
    hash(input: Uint8Array): Uint8Array
    ID: OPRFCiphersuite
}
