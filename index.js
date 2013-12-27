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
					throw scrypt.errorObject(1, "Argument error: expecting maxtime as a number");
				}

				if (i-startIndex == 1) {
					throw scrypt.errorObject(1, "Argument error: expecting maxmem as a number");
				}
				
				if (i-startIndex == 2) {
					throw scrypt.errorObject(1, "Argument error: expecting maxmemfrac as a number");
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

	return function() {	
		var args = Array.prototype.slice.apply(arguments),
			paramsObject;

		//Determine if translation function is needed
		if (args.length > 1 && typeof args[1] !== "object") {
			paramsObject = parseScryptParameters(arguments, 1); 
		}

		if (typeof args[args.length-1] === "function") {
			var buffer = (typeof args[args.length-2] === "boolean") ? args[args.length-2] : false;
			if (typeof args[args.length-2] === "boolean") {
				args.splice(args.length-2,1);
			}

			args[args.length-1] = asyncHandler(args[args.length-1], buffer);

			if (typeof paramsObject !== "undefined") {
				params(paramsObject.maxtime, paramsObject.maxmem, paramsObject.maxmemfrac, function(err, scryptParams) {
					args.splice(1,Object.keys(paramsObject).length,scryptParams);
					passwordHash.apply(this, args);
				});
			} else {
				passwordHash.apply(this, args);
			}
		} else {
			var buffer = (typeof args[args.length-1] === "boolean") ? args[args.length-1] : false;
			if (typeof args[args.length-1] === "boolean") {
				args.splice(args.length-1,1);
			}

			if (typeof paramsObject !== "undefined") {
				var scryptParams = params(paramsObject.maxtime, paramsObject.maxmem, paramsObject.maxmemfrac);
				args.splice(1, Object.keys(paramsObject).length, scryptParams);
			}

			if (buffer) {
				return passwordHash.apply(this, args);
			} else {
				return passwordHash.apply(this, args).toString("base64");
			}
		}
	}
}(scrypt.passwordHash, scrypt.params);

//
// Backward Compatbility
//
scrypt.passwordHashSync = scrypt.passwordHash;
scrypt.verifyHashSync = scrypt.verifyHash;

module.exports = scrypt;
