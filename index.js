var scrypt = require('./build/Release/scrypt');

//
//Create function instances
//
scrypt.passwordHash = scrypt.Hash();
scrypt.verifyHash = scrypt.Verify();
scrypt.hash = scrypt.Hash();
scrypt.verify = scrypt.Verify();
scrypt.params = scrypt.Params();
scrypt.kdf = scrypt.KDF();


//
//Parses input arguments for scrypt parameter object or translation function inputs
//
function parseScryptParameters(args, startIndex) {
	var	i = 0,
		paramsObject = {};

	for (i=startIndex; i < startIndex+3 && typeof args[i] != "undefined"; i++) {
		if (i - startIndex > 0 && (typeof args[i] === "function" || typeof args[i] === "boolean")) {
			break;
		}

		switch(typeof args[i]) {	
			case "number": 
				if (i - startIndex == 0) {
					paramsObject.maxtime = args[i];
				}
				
				if (i - startIndex == 1) {
					paramsObject.maxmem = args[i];
				}
				
				if (i - startIndex == 2) {
					paramsObject.maxmemfrac = args[i];
				}

				break;

			default:
				if (i-startIndex == 0) {
					throw scrypt.errorObject(1, "expecting maxtime as a number");
				}

				if (i-startIndex == 1) {
					throw scrypt.errorObject(1, "expecting maxmem as a number");
				}
				
				if (i-startIndex == 2) {
					throw scrypt.errorObject(1, "expecting maxmemfrac as a number");
				}

				break;
		}
	}

	return paramsObject;
}

//
// Scrypt Password Hash
//
scrypt.passwordHash = function(passwordHash, params) {

	var retFunction = function() {	
		var args = Array.prototype.slice.apply(arguments),
			paramsObject;

//Determine if there are too little arguments
		if (args.length < 2) {
			throw scrypt.errorObject(1, "wrong number of arguments - at least two arguments are needed - key and scrypt parameters JSON object");
		}

		//Determine if translation function is needed
		if (args.length > 1 && typeof args[1] !== "object" && typeof args[1] !== "function") {
			paramsObject = parseScryptParameters(arguments, 1); 
		}

		//Asyc
		if (typeof args[args.length-1] === "function") {
			if (typeof paramsObject !== "undefined") {
				params(paramsObject.maxtime, paramsObject.maxmem, paramsObject.maxmemfrac, function(err, scryptParams) {
					args.splice(1,Object.keys(paramsObject).length,scryptParams);
					passwordHash(args[0], args[1], args[2]);
				});
			} else {
				passwordHash(args[0], args[1], args[2]);
			}
		//Sync
		} else {
			if (typeof paramsObject !== "undefined") {
				var scryptParams = params(paramsObject.maxtime, paramsObject.maxmem, paramsObject.maxmemfrac);
				args.splice(1, Object.keys(paramsObject).length, scryptParams);
			}

			return passwordHash(args[0], args[1]);
		}
	}
	retFunction.config = passwordHash.config;

	return retFunction;
}(scrypt.passwordHash, scrypt.params);

//
// Backward Compatbility
//
scrypt.passwordHash.config.keyEncoding = "ascii";
scrypt.passwordHash.config.outputEncoding = "base64";
scrypt.verifyHash.config.hashEncoding = "base64";
scrypt.verifyHash.config.keyEncoding = "ascii";

scrypt.passwordHashSync = scrypt.passwordHash;
scrypt.verifyHashSync = scrypt.verifyHash;

module.exports = scrypt;
