(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "./src/errors.js", "./src/mlKem512.js", "./src/mlKem768.js", "./src/mlKem1024.js"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.MlKem1024 = exports.MlKem768 = exports.MlKem512 = exports.MlKemError = void 0;
    var errors_js_1 = require("./src/errors.js");
    Object.defineProperty(exports, "MlKemError", { enumerable: true, get: function () { return errors_js_1.MlKemError; } });
    var mlKem512_js_1 = require("./src/mlKem512.js");
    Object.defineProperty(exports, "MlKem512", { enumerable: true, get: function () { return mlKem512_js_1.MlKem512; } });
    var mlKem768_js_1 = require("./src/mlKem768.js");
    Object.defineProperty(exports, "MlKem768", { enumerable: true, get: function () { return mlKem768_js_1.MlKem768; } });
    var mlKem1024_js_1 = require("./src/mlKem1024.js");
    Object.defineProperty(exports, "MlKem1024", { enumerable: true, get: function () { return mlKem1024_js_1.MlKem1024; } });
});
