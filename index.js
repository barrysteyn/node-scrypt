"use strict";

var scryptNative = require("./build/Release/scrypt");
//module.exports = scrypt;
//var scryptParameters = scrypt.ParamsSync(10, 10240, 0.9);
//console.log(scryptParameters);

var CheckEmptyArguments = function(args, message) {
	var err_msg = (message !== undefined) ? message : "No arguments are present";

	if (args.length === 0) {
		var error = new Error(err_msg);
		error.name = "SyntaxError";
		throw error;
	}
}

var ProcessParamsSyncArguments = function(args) {
	var error = undefined;

	CheckEmptyArguments(args, "No arguments present, at least one argument is needed - the maxtime");

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
			error = new Error(propertyName + " must be a number");
			error.name = "TypeError";
		}

		// Specific argument checks
		if (!error) {
			switch (i) {
				case 0: //maxtime
					if (args[0] <= 0) {
						error = new Error(propertyName + " must be greater than 0");
						error.name = "RangeError";
					}
					break;

				case 1: //maxmem
					if (args[1] !== parseInt(args[1], 10)) {
						error = new Error(propertyName + " must be an integer");
						error.name = "TypeError";
					}

					if (!error && args[1] < 0) {
						error = new Error(propertyName + " must be greater than or equal to 0")
                                                error.name = "RangeError";
					}
					break;

				case 2: //max_memfrac
					if (args[2] < 0.0 || args[2] > 1.0) {
						error = new Error(propertyName + " must be between 0.0 and 1.0 inclusive")
						error.name = "RangeError";
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
	CheckEmptyArguments(args, "No arguments present, at least two arguments are needed - the maxtime and callback function");

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
		error = new Error("No callback function present");
		error.name = "SyntaxError";
		throw error;
	}

	// callback cannot be first argument
	if (callback_index === 0) {
		error = new Error("At least one argument is needed before the callback - the maxtime");
		error.name = "SyntaxError";
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

//Actual Scrypt Object
var Scrypt = {

	ParamsSync: function() {
		var args = ProcessParamsSyncArguments(arguments);
		return scryptNative.ParamsSync(args[0], args[1], args[2]);
	},

	Params: function() {
		var args = ProcessParamsASyncArguments(arguments);
		scryptNative.Params(args[0], args[1], args[2], args[3]);
	}
};

module.exports = Scrypt;
