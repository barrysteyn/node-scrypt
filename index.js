var scrypt = require('./build/Release/scrypt');

//For backward compatibility, make function aliases
scrypt.passwordHashSync = scrypt.passwordHash;

module.exports = scrypt;
