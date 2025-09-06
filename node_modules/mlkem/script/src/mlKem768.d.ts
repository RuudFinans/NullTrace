import { MlKemBase } from "./mlKemBase.js";
/**
 * Represents the MlKem768 class, which extends the MlKemBase class.
 *
 * This class extends the MlKemBase class and provides specific implementation for MlKem768.
 *
 * @remarks
 *
 * MlKem768 is a specific implementation of the ML-KEM key encapsulation mechanism.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { MlKem768 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = new MlKem768();
 * const [pkR, skR] = await recipient.generateKeyPair();
 *
 * const sender = new MlKem768();
 * const [ct, ssS] = await sender.encap(pkR);
 *
 * const ssR = await recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export declare class MlKem768 extends MlKemBase {
    _k: number;
    _du: number;
    _dv: number;
    _eta1: number;
    _eta2: number;
    constructor();
}
//# sourceMappingURL=mlKem768.d.ts.map