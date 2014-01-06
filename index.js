var scrypt = require('./build/Release/scrypt');

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
	var asyncHandler = function(handler, buffer) {
		if (typeof buffer === "undefined" || typeof buffer !== "boolean") {
			buffer = false;
		}

		return function(err, passwordHash) {
			if (buffer || typeof passwordHash !== "object") {
				handler(err, passwordHash);
			} else {
				handler(err, passwordHash.toString("base64"));
			}
		}
	}

	var retFunction = function() {	
		var args = Array.prototype.slice.apply(arguments),
			paramsObject;

		//Determine if translation function is needed
		if (args.length > 1 && typeof args[1] !== "object" && typeof args[1] !== "function") {
			paramsObject = parseScryptParameters(arguments, 1); 
		}

		if (typeof args[args.length-1] === "function") {
			if (typeof paramsObject !== "undefined") {
				params(paramsObject.maxtime, paramsObject.maxmem, paramsObject.maxmemfrac, function(err, scryptParams) {
					args.splice(1,Object.keys(paramsObject).length,scryptParams);
					passwordHash.apply(this, args);
				});
			} else {
				passwordHash.apply(this, args);
			}
		} else {
			if (typeof paramsObject !== "undefined") {
				var scryptParams = params(paramsObject.maxtime, paramsObject.maxmem, paramsObject.maxmemfrac);
				args.splice(1, Object.keys(paramsObject).length, scryptParams);
			}

			return passwordHash.apply(this, args);
		}
	}
	retFunction.config = passwordHash.config;

	return retFunction;
}(scrypt.passwordHash, scrypt.params);

//
// Backward Compatbility
//
scrypt.passwordHashSync = scrypt.passwordHash;
scrypt.verifyHashSync = scrypt.verifyHash;

module.exports = scrypt;
