export declare function byte(n: number): number;
export declare function int16(n: number): number;
export declare function uint16(n: number): number;
export declare function int32(n: number): number;
export declare function uint32(n: number): number;
/**
 * compares two arrays
 * @returns 1 if they are the same or 0 if not
 */
export declare function constantTimeCompare(x: Uint8Array, y: Uint8Array): number;
export declare function equalUint8Array(x: Uint8Array, y: Uint8Array): boolean;
export declare function loadCrypto(): Promise<Crypto>;
export declare function prf(len: number, seed: Uint8Array, nonce: number): Uint8Array;
export declare function byteopsLoad24(x: Uint8Array): number;
export declare function byteopsLoad32(x: Uint8Array): number;
//# sourceMappingURL=utils.d.ts.map