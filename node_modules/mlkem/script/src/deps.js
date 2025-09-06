(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "@noble/hashes/sha3"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.shake256 = exports.shake128 = exports.sha3_512 = exports.sha3_256 = void 0;
    var sha3_1 = require("@noble/hashes/sha3");
    Object.defineProperty(exports, "sha3_256", { enumerable: true, get: function () { return sha3_1.sha3_256; } });
    Object.defineProperty(exports, "sha3_512", { enumerable: true, get: function () { return sha3_1.sha3_512; } });
    Object.defineProperty(exports, "shake128", { enumerable: true, get: function () { return sha3_1.shake128; } });
    Object.defineProperty(exports, "shake256", { enumerable: true, get: function () { return sha3_1.shake256; } });
});
