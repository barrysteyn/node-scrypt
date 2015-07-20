"use strict";

var ScryptNative = require("./build/Release/scrypt");
//module.exports = scrypt;
//var scryptParameters = scrypt.ParamsSync(10, 10240, 0.9);
//console.log(scryptParameters);

var CheckNumberOfArguments = function(args, message, numberOfArguments) {
	var err_msg = (message !== undefined) ? message : "No arguments are present";

	if (args.length < numberOfArguments) {
		var error = new SyntaxError(err_msg);
		throw error;
	}
}

//
// Description Here
//
var CheckCallbackArgument = function(args, callback_index, needed_position, message) {
	if (callback_index === undefined) {
		var message = (args.length)
			? "No callback function present"
			: "No arguments present";
		var error = new SyntaxError(message);
		throw error;
	}

	if (callback_index < needed_position) {
		var error = new SyntaxError(message);
		throw error;
	}
}
//
// Description here
//
var CheckScryptParametersObject = function(params) {
	var error = undefined;

	if (typeof params !== "object") {
		var error = new TypeError("Scrypt parameters type is incorrect: It must be a JSON object");
	}

	if (!error && !params.hasOwnProperty("N")) {
		var error = new TypeError("Scrypt params object does not have 'N' property present");
	}

	if (!error && params.N !== parseInt(params.N)) {
		var error = new TypeError("Scrypt params object 'N' property is not an integer");
	}

	if (!error && !params.hasOwnProperty("r")) {
		var error = new TypeError("Scrypt params object does not have 'r' property present");
	}

	if (!error && params.r !== parseInt(params.r)) {
		var error = new TypeError("Scrypt params object 'r' property is not an integer");
	}

	if (!error && !params.hasOwnProperty("p")) {
		var error = new TypeError("Scrypt params object does not have 'p' property present");
	}

	if (!error && params.p !== parseInt(params.p)) {
		var error = new TypeError("Scrypt params object 'p' property is not an integer");
	}

	if (error) {
		error.propertyName = "Scrypt parameters object";
		error.propertyValue = params;
		throw error;
	}
}

var ProcessParamsSyncArguments = function(args) {
	var error = undefined;

	CheckNumberOfArguments(args, "At least one argument is needed - the maxtime", 1);

	// Set defaults (if necessary)
	if (args[1] === undefined) args[1] = 0; //maxmem default to 0
	if (args[2] === undefined) args[2] = 0.5; //max_memfrac default to 0.5

	for(var i=0; i < Math.min(3, args.length); i++) {
		var propertyName = (function() {
			if (i === 0) return "maxtime";
			if (i === 1) return "maxmem";
			if (i === 2) return "max_memfrac";
		})();

		// All args must be of type number
		if (!error && typeof args[i] !== "number") {
			error = new TypeError(propertyName + " must be a number");
		}

		// Specific argument checks
		if (!error) {
			switch (i) {
				case 0: //maxtime
					if (args[0] <= 0) {
						error = new RangeError(propertyName + " must be greater than 0");
					}
					break;

				case 1: //maxmem
					if (args[1] !== parseInt(args[1], 10)) {
						error = new TypeError(propertyName + " must be an integer");
					}

					if (!error && args[1] < 0) {
						error = new RangeError(propertyName + " must be greater than or equal to 0")
					}
					break;

				case 2: //max_memfrac
					if (args[2] < 0.0 || args[2] > 1.0) {
						error = new RangeError(propertyName + " must be between 0.0 and 1.0 inclusive")
					}
					break;
			}
		}

		// Throw error if necessary
		if (error) {
			error.propertyName = propertyName;
			error.propertyValue = args[i];
			throw error;
		}
	}

	return args;
}

var ProcessParamsASyncArguments = function(args) {
	var error = undefined;

	// find callback
	var callback_index = (function(){
		for (var i=0; i < args.length; i++) {
			if (typeof args[i] === "function") {
				return i;
			}
		}
	})();

	// check callback exists
	if (callback_index === undefined) {
		if (args.length === 0)
			error = new SyntaxError("No arguments present");
		else
			error = new SyntaxError("No callback function present");
		throw error;
	}

	// callback cannot be first argument
	if (callback_index === 0) {
		error = new SyntaxError("At least one argument is needed before the callback - the maxtime", 1);
		throw error;
	}

	// remove callback function from args and
	// put it in it's own variable. This allows
	// sync check to be used (DRY)
	var callback = args[callback_index];
	delete args[callback_index];
	var args = ProcessParamsSyncArguments(args);
	args[3] = callback;

	return args;
}

var ProcessKDFSyncArguments = function(args) {
	CheckNumberOfArguments(args, "At least two arguments are needed - the key and the Scrypt paramaters object", 2)

	//
	// Check key argument
	//
	if (typeof args[0] === "string")
		// Convert string to buffer (if necessary)
		args[0] = new Buffer(args[0]);
	else if (!Buffer.isBuffer(args[0])) {
		var error = new TypeError("key type is incorrect: It can only be of type string or Buffer");
		error.propertyName = "key";
		error.propertyValue = args[0];
		throw error;
	}

	//
	// Check Scrypt Parameters object
	//
	CheckScryptParametersObject(args[1])

	return args;
}

var ProcessKDFASyncArguments = function(args) {
	//
	// Check callback function
	//
	var callback_index = (function(){
		for (var i=0; i < args.length; i++) {
			if (typeof args[i] === "function") {
				return i;
			}
		}
	})();
	CheckCallbackArgument(args, callback_index, 2, "At least two arguments are needed before the call back function - the key and the Scrypt parameters object");

	//
	// Check other arguments (with sync version)
	//
	return ProcessKDFSyncArguments(args);
}

var ProcessVerifySyncArguments = function(args) {
	CheckNumberOfArguments(args, "At least two arguments are needed - the KDF and the key", 2);

	//
	// Check KDF
	//
	if (typeof args[0] === "string")
		// Convert string to buffer (if necessary)
		args[0] = new Buffer(args[0]);
	else if (!Buffer.isBuffer(args[0])) {
		var error = new TypeError("KDF type is incorrect: It can only be of type string or Buffer");
		error.propertyName = "KDF";
		error.propertyValue = args[0];
		throw error;
	}

	//
	// Check Key
	//
	if (typeof args[1] === "string")
		// Convert string to buffer (if necessary)
		args[1] = new Buffer(args[1]);
	else if (!Buffer.isBuffer(args[1])) {
		var error = new TypeError("key type is incorrect: It can only be of type string or Buffer");
		error.propertyName = "key";
		error.propertyValue = args[1];
		throw error;
	}

	return args;
}

var ProcessVerifyASyncArguments = function(args) {
	//
	// Check callback function
	//
	var callback_index = (function(){
		for (var i=0; i < args.length; i++) {
			if (typeof args[i] === "function") {
				return i;
			}
		}
	})();
	CheckCallbackArgument(args, callback_index, 2, "At least two arguments are needed before the callback function - the KDF and the key");

	//
	// Check other arguments (with sync version)
	//
	return ProcessVerifySyncArguments(args);
}

var ProcessHashSyncArguments = function(args) {
	CheckNumberOfArguments(args, "At least four arguments are needed - the key to hash, the scrypt params object, the output length of the hash and the salt", 4);

	//
	// Check Key
	//
	if (typeof args[0] === "string")
		// Convert string to buffer (if necessary)
		args[0] = new Buffer(args[0]);
	else if (!Buffer.isBuffer(args[0])) {
		var error = new TypeError("Key type is incorrect: It can only be of type string or Buffer");
		error.propertyName = "KDF";
		error.propertyValue = args[0];
		throw error;
	}

	//
	// Check Scrypt Parameters object
	//
	CheckScryptParametersObject(args[1])

	//
	// Check the hash output length
	//
	if (typeof args[2] !== "number" || args[2] !== parseInt(args[2],10)) {
		error = new TypeError("hash length must be an integer");
		throw error;
	}

	//
	// Check Salt
	//
	if (typeof args[3] === "string")
		// Convert string to buffer (if necessary)
		args[3] = new Buffer(args[3]);
	else if (!Buffer.isBuffer(args[3])) {
		var error = new TypeError("Salt type is incorrect: It can only be of type string or Buffer");
		error.propertyName = "salt";
		error.propertyValue = args[3];
		throw error;
	}

	return args;
}

var ProcessHashASyncArguments = function(args) {
	//
	// Check callback function
	//
	var callback_index = (function(){
		for (var i=0; i < args.length; i++) {
			if (typeof args[i] === "function") {
				return i;
			}
		}
	})();
	CheckCallbackArgument(args, callback_index, 4, "At least four arguments are needed before the callback - the key to hash, the scrypt params object, the output length of the hash and the salt");

	//
	// Check other arguments (with sync version)
	//
	return ProcessHashSyncArguments(args);
}

//
// Scrypt Object
//
var Scrypt = {
	ParamsSync: function() {
		var args = ProcessParamsSyncArguments(arguments);
		return ScryptNative.ParamsSync(args[0], args[1], args[2]);
	},

	Params: function() {
		var args = ProcessParamsASyncArguments(arguments);
		ScryptNative.Params(args[0], args[1], args[2], args[3]);
	},

	KDFSync: function() {
		var args = ProcessKDFSyncArguments(arguments);
		return ScryptNative.KDFSync(args[0], args[1]);
	},

	KDF: function() {
		var args = ProcessKDFASyncArguments(arguments);
		ScryptNative.KDF(args[0], args[1], args[2]);
	},

	VerifySync: function() {
		var args = ProcessVerifySyncArguments(arguments);
		return ScryptNative.VerifySync(args[0], args[1]);
	},

	Verify: function() {
		var args = ProcessVerifyASyncArguments(arguments);
		ScryptNative.Verify(args[0], args[1], args[2]);
	},

	HashSync: function() {
		var args = ProcessHashSyncArguments(arguments);
		return ScryptNative.HashSync(args[0], args[1], args[2], args[3]);
	},

	Hash: function() {
		var args = ProcessHashASyncArguments(arguments);
		ScryptNative.Hash(args[0], args[1], args[2], args[3], args[4]);
	}
};

//Scrypt.KDF();

module.exports = Scrypt;
