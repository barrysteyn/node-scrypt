var scrypt = require("./")();
scrypt.kdf.config.saltEncoding = "ascii";

var scrypt2 = require("./")();

console.log(scrypt2.kdf.config.saltEncoding);
console.log(scrypt.kdf.config.saltEncoding);
