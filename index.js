var scrypt = require('./build/Release/scrypt');

//
//Parses input arguments for scrypt parameter object or translation function inputs
//
function parseScryptParameters(args, scryptInfo, start) {
	var startIndex = (typeof start == "number" && start >= 0) ? startIndex = start : startIndex = 0,
		i = 0;

	function translationNeeded() {
		return (typeof scryptInfo.maxtime != "undefined" || typeof scryptInfo.maxmem != "undefined" || typeof scryptInfo.maxmemfrac != "undefined");
	}

	for (i=startIndex; i < startIndex+3 && typeof args[i] != "undefined"; i++) {
		if (typeof args[i] != "object" && typeof args[i] != "number") {
			if (!translationNeeded() && typeof scryptInfo.scryptParams == "undefined") {
				throw scrypt.errorObject(1,"Argument error: Expecting either maxtime, maxmem and maxmem_frac or scrypt params");
			}

			return i;
		}

		switch(typeof args[i]) {
			case "object":
				if (!translationNeeded()) {
					scryptInfo.scryptParams = args[i];
					return i;
				} else {
					throw scrypt.errorObject(1, "Argument error: Cannot mix params with translation params");
				}
			break;

			case "number": 
				if (i-startIndex == 0) 
					scryptInfo.maxtime = args[i];

				if (i-startIndex == 1)
					scryptInfo.maxmem = args[i];

				if (i-startIndex == 2) {
					scryptInfo.maxmemfrac = args[i];
					return i;
				}
			break;
		}
	}
	
	return i;
}

//
//Parses arguments specific to the hash function
//
function parsePwdHashArguments(args, scryptArgs) {
	var startIndex = parseScryptParameters(args, scryptArgs, 1);
	for (var i = startIndex; i < args.length; i++) {	

		if (typeof args[i] == "function") {
			scryptArgs.callback = args[i];
			break;
		}

		switch (i - startIndex) {
			case 0:
				if (typeof args[i] != "string") //must be string if encoding is present
					throw scrypt.errorObject(1,"Argument error: encoding must be a string");

				scryptArgs.encoding = args[i].toLowerCase();
				break;
			case 1:
				if (typeof args[i] != "number") //must be a number of length is present
					throw scrypt.errorObject(1,"Argument error: length must be a number");

				scryptArgs.length = args[i];
				break;
		}			
	}
}

//
// Scrypt Password Hash
//
scrypt.passwordHash = function(passwordHash, params) {
	return function() {	
		var password = arguments[0], //Always assume that first argument will be password
			passwordHashArgs = {};

		parsePwdHashArguments(arguments, passwordHashArgs);

		if (passwordHashArgs.callback) {

			//Asynchronous
			if (!passwordHashArgs.scryptParams) {
				params(passwordHashArgs.maxtime, passwordHashArgs.maxmem, passwordHashArgs.maxmemfrac, function(err, scryptParams) {
					passwordHash(password, scryptParams, passwordHashArgs.encoding, passwordHashArgs.length, passwordHashArgs.callback);
				});
			} else {
				passwordHash(password, passwordHashArgs.scryptParams, passwordHashArgs.encoding, passwordHashArgs.length, passwordHashArgs.callback);
			}
		} else {

			//Synchronous
			if (!passwordHashArgs.scryptParams) // translation function is needed
				passwordHashArgs.scryptParams = params(passwordHashArgs.maxtime, passwordHashArgs.maxmem, passwordHashArgs.maxmemfrac);

			return passwordHash(password, passwordHashArgs.scryptParams, passwordHashArgs.encoding, passwordHashArgs.length);
		}
	}
}(scrypt.passwordHash, scrypt.params);

//
// Scrypt Verify Password Hash
//
scrypt.verifyHash = function(verifyHash) {
	return function() {
		arguments[0] = (Buffer.isBuffer(arguments[0])) ? arguments[0].toString("base64") : arguments[0];
		return verifyHash.apply(this, arguments);
	}
}(scrypt.verifyHash);

//
// Backward Compatbility
//
scrypt.passwordHashSync = scrypt.passwordHash;
scrypt.verifyHashSync = scrypt.verifyHash;

module.exports = scrypt;
