import { MlKemBase } from "./mlKemBase.js";
/**
 * Represents the MlKem512 class.
 *
 * This class extends the MlKemBase class and provides specific implementation for MlKem512.
 *
 * @remarks
 *
 * MlKem512 is a specific implementation of the ML-KEM key encapsulation mechanism.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { MlKem512 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { MlKem512 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = new MlKem512();
 * const [pkR, skR] = await recipient.generateKeyPair();
 *
 * const sender = new MlKem512();
 * const [ct, ssS] = await sender.encap(pkR);
 *
 * const ssR = await recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export declare class MlKem512 extends MlKemBase {
    _k: number;
    _du: number;
    _dv: number;
    _eta1: number;
    _eta2: number;
    /**
     * Constructs a new instance of the MlKem512 class.
     */
    constructor();
    /**
     * Samples a vector of polynomials from a seed.
     * @internal
     * @param sigma - The seed.
     * @param offset - The offset.
     * @param size - The size.
     * @returns The sampled vector of polynomials.
     */
    protected _sampleNoise1(sigma: Uint8Array, offset: number, size: number): Array<Array<number>>;
}
//# sourceMappingURL=mlKem512.d.ts.map