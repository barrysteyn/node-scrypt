var test = require('tap').test;
var scrypt = require('../');
var passwordString = "This is the test password";
var passwordStringObject = new String(passwordString);
var passwordBuffer = new Buffer(passwordString);
var maxtime_passwordhash = 0.05; 
var message = "This is a message";
var scryptParameters = {"N":1, "r":1, "p":1}

//These error results are taken verbatim from src/node-boilerplate/scrypt_common.h
var JSARG=1; //Error in JavaScript land: Argument mismatch
var ADDONARG=2; //Error resulting from argument mismatch in the node addon module
var PARMOBJ=3; //Scrypt generated errors
var SCRYPT=4; //Scrypt generated errors

/*
 * Logic Tests
 */

test("KDF - Test vector 1", function(t) {
	var buf = new Buffer("");
	var res = scrypt.KDF(buf,{"N":16,"r":1,"p":1},64,"");
	t.equal(res.hash.toString("hex"),"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906","Synchronous test: first test vector is correctly returned");	

	scrypt.KDF(buf, {"N":16,"r":1,"p":1},64,"", function(err, res) {
		t.equal(res.hash.toString("hex"),"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906","Asynchronous test: first test vector is correctly returned");
		t.end();
	});
});

test("KDF - Test vector 2", function(t) {
	var buf = new Buffer("NaCl");
	var res = scrypt.KDF("password",{"N":1024,"r":8,"p":16},64,buf);
	t.equal(res.hash.toString("hex"),"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640","Synchronous test: second test vector is correctly returned");	

	scrypt.KDF("password", {"N":1024,"r":8,"p":16},64,buf, function(err, res) {
		t.equal(res.hash.toString("hex"),"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640","Synchronous test: second test vector is correctly returned");	
		t.end();
	});
});

test("KDF - Test vector 3", function(t) {
	var buf = new Buffer("pleaseletmein");
	var salt = new Buffer("SodiumChloride");
	var res = scrypt.KDF(buf,{"N":16384,"r":8,"p":1},64,salt);
	t.equal(res.hash.toString("hex"),"7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887","Synchronous test: third test vector is correctly returned");	

	scrypt.KDF(buf, {"N":16384,"r":8,"p":1},64,salt, function(err, res) {
		t.equal(res.hash.toString("hex"),"7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887","Asynchronous test: third test vector is correctly returned");
		t.end();
	});
});

test("KDF - Random salt added by default", function(t) {
	var key = new Buffer("key");	
	var hash1 = scrypt.KDF(key, scryptParameters);
	var hash2 = scrypt.KDF(key, scryptParameters);
	t.notEqual(hash1.hash.toString(), hash2.hash.toString(), "Synchronous: hashes that are returned are not equal. This is correct due to random salt that was added");
	t.notEqual(hash1.salt.toString(), hash2.salt.toString(), "Synchronous: salts that are returned are not equal");

	scrypt.KDF(key, scryptParameters, function(err, hash1) {
		scrypt.KDF(key, scryptParameters, function(err, hash2) {
			t.notEqual(hash1.hash.toString(), hash2.hash.toString(), "Asynchronous: hashes that are returned are not equal. This is correct due to random salt that was added");
			t.notEqual(hash1.salt.toString(), hash2.salt.toString(), "Asynchronous: salts that are returned are not equal");
			t.end();
		});
	});
});

test("KDF - Deterministic non-random salt added manually", function(t) {
	var key = new Buffer("key");
	var salt = "salt";	
	console.log(scryptParameters);
	var hash1 = scrypt.KDF(key, scryptParameters, 64, "salt");
	var hash2 = scrypt.KDF(key, scryptParameters, 64, "salt");
	t.equal(hash1.hash.toString(), hash2.hash.toString(), "Synchronous: hashes that are returned are equal. This is correct due to non-random salt that was added");
	t.equal(hash1.salt.toString(), hash2.salt.toString(), "Synchronous: salts that are returned are identical");

	scrypt.KDF(key, scryptParameters, 64, salt, function(err, hash1) {
		scrypt.KDF(key, scryptParameters, 64, salt, function(err, hash2) {
			t.equal(hash1.hash.toString(), hash2.hash.toString(), "Asynchronous: hashes that are returned are equal. This is correct due to non-random salt that was added");
			t.equal(hash1.salt.toString(), hash2.salt.toString(), "Asynchronous: salts that are returned are identical");
			t.end();
		});
	});
});

//test("KDF - Consistency test", function(t) {
//	var key = new Buffer("key");
	
//});

/*test("KDF - Test vector 4", function(t) { //This test takes too long to perform for continuous integration
	var res = scrypt.KDF("pleaseletmein",{"N":1048576,"r":8,"p":1},64,"SodiumChloride");
	t.equal(res.hash.toString("hex"),"2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4", "Synchronous test: fourth test vector is correctly returned");	

	scrypt.KDF("pleaseletmein", {"N":1048576,"r":8,"p":1},64,"SodiumChloride", function(err, res) {
		t.equal(res.hash.toString("hex"),"2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4","Asynchronous test: fourth test vector is correctly returned");
		t.end();
	});
});*/

/*test("Password Hash/Verify - Consistency", function(t) {
	var buf = new Buffer("pleaseletmein");
	var salt = new Buffer("SodiumChloride");
	var res = scrypt.KDF(buf,{"N":16384,"r":8,"p":1},64,salt);
	t.equal(res.hash.toString("hex"),"7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887","Synchronous test: third test vector is correctly returned");	

	scrypt.KDF(buf, {"N":16384,"r":8,"p":1},64,salt, function(err, res) {
		t.equal(res.hash.toString("hex"),"7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887","Asynchronous test: third test vector is correctly returned");
		t.end();
	})
});*/
/*
 * Argument Tests
 */

//
// Translation Function (Parameter) Tests */
//

//General (applies to both async and sync)
test("Pick Parameters (Translation function): - no arguments are present", function(t) {
	try {
		scrypt.params();
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least argument is needed - in this case, no arguments were given");
		t.deepEqual(err, scrypt.errorObject(ADDONARG, "at least one argument is needed - the maxtime"), "The correct message object is returned, namely:"+ JSON.stringify(err));
		t.end();
	}
});

test("Pick Parameters (Translation function): incorrect argument type", function(t) {
	try {
		scrypt.params("abc");
	} catch (err) {
		t.ok(err, "An error was correctly thrown because an incorrect type was passed to the function - in this case, the maxtime was passed as a string, but a number is expected");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"maxtime argument must be a number"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Pick Parameters (Translation function): incorrect argument type", function(t) {
	try {
		scrypt.params(0);
	} catch (err) {
		t.ok(err, "An error was correctly thrown because maxtime was passed as a number <= 0");
		t.deepEqual(err, scrypt.errorObject(ADDONARG, "maxtime must be greater than 0"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Pick Parameters (Translation function): incorrect argument type", function(t) {
	try {
		scrypt.params(1, "abc");
	} catch (err) {
		t.ok(err, "An error was correctly thrown because an incorrect type was passed to the function - in this case, the maxmem was passed as a string, but a number is expected");
		t.deepEqual(err,scrypt.errorObject(ADDONARG, "maxmem argument must be a number"), "The correct object is returned, namely: "+ JSON.stringify(err));
		t.end();
	}
});

test("Pick Parameters (Translation function): incorrect argument type", function(t) {
	try {
		scrypt.params(1, 0.5, "abc");
	} catch (err) {
		t.ok(err, "An error was correctly thrown because an incorrect type was passed to the function - in this case, the maxmemfrac was passed as a string, but a number is expected");
		t.deepEqual(err, scrypt.errorObject(ADDONARG, "max_memfrac argument must be a number"), "The correct object is returned, namely: " + JSON.stringify(err.message));
		t.end();
	}
});

//Asynchronous
test("Pick Parameters (Asynchronous): incorrect argument - no arguments before callback", function(t) {
	try {
		scrypt.params(function(){});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least argument is needed before the callback - in this case, no arguments were given");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"at least one argument is needed before the callback - the maxtime"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Asynchronous: Pick parameters returns an object given correct inputs of just maxtime", function(t) {
	scrypt.params(2, function(err, parameters) {
		t.type(parameters,"object","Returned entity is an object");
		t.type(parameters.N, "number","N is present in object and is of type number");
		t.type(parameters.r, "number","r is present in object and is of type number");
		t.type(parameters.p, "number","p is present in object and is of type number");
		t.end();
	});
});

test("Asynchronous: Pick parameters returns an object given correct inputs of just maxtime and max_memfrac", function(t) {
	scrypt.params(2, 0.5, function(err, parameters) {
		t.type(parameters,"object","Returned entity is an object");
		t.type(parameters.N, "number","N is present in object and is of type number");
		t.type(parameters.r, "number","r is present in object and is of type number");
		t.type(parameters.p, "number","p is present in object and is of type number");
		t.end();
	});
});

test("Asynchronous: Pick parameters returns an object given correct inputs of maxtime, max_memfrac and maxmem", function(t) {
	scrypt.params(2, 0.5, 1, function(err, parameters) {
		t.type(parameters,"object","Returned entity is an object");
		t.type(parameters.N, "number","N is present in object and is of type number");
		t.type(parameters.r, "number","r is present in object and is of type number");
		t.type(parameters.p, "number","p is present in object and is of type number");
		t.end();
	});
});

//Synchronous
test("Synchronous: Pick parameters returns an object given correct inputs of just maxtime", function(t) {
	parameters = scrypt.params(2);
	t.type(parameters,"object","Returned entity is an object");
	t.type(parameters.N, "number","N is present in object and is of type number");
	t.type(parameters.r, "number","r is present in object and is of type number");
	t.type(parameters.p, "number","p is present in object and is of type number");
	t.end();
});

test("Synchronous: Pick parameters returns an object given correct inputs of just maxtime and max_memfrac", function(t) {
	parameters = scrypt.params(2, 0.5);
	t.type(parameters,"object","Returned entity is an object");
	t.type(parameters.N, "number","N is present in object and is of type number");
	t.type(parameters.r, "number","r is present in object and is of type number");
	t.type(parameters.p, "number","p is present in object and is of type number");
	t.end();
});

test("Synchronous: Pick parameters returns an object given correct inputs of maxtime, max_memfrac and maxmem", function(t) {
	parameters = scrypt.params(2, 0.5, 1);
	t.type(parameters,"object","Returned entity is an object");
	t.type(parameters.N, "number","N is present in object and is of type number");
	t.type(parameters.r, "number","r is present in object and is of type number");
	t.type(parameters.p, "number","p is present in object and is of type number");
	t.end();
});

//
// Password Hash Tests
//

//General (both async and sync)
test("Password Hash: incorrect arguments - no arguments present", function(t) {
	try {
		scrypt.passwordHash();
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least two arguments are needed - in this case, no arguments were given");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"wrong number of arguments - at least two arguments are needed - password and scrypt parameters JSON object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - only one argument present", function(t) {
	try {
		scrypt.passwordHash(passwordString);
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least two arguments are needed - in this case, only one was present, namely the password");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"wrong number of arguments - at least two arguments are needed - password and scrypt parameters JSON object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected password is not a string", function(t) {
	try {
		scrypt.passwordHash(1232, scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test: An error was correctly thrown because the password type was incorrect - in this case, it was of type number, but it should be of type string or buffer");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password must be a buffer or a string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	
	try {
		scrypt.passwordHash(1232, scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: An error was correctly thrown because the password type was incorrect - in this case, it was of type number, but it should be of type string or buffer");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password must be a buffer or a string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(passwordString, {});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it is an empty object");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"N value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	
	try {
		scrypt.passwordHash(passwordString, {}, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it is an empty object");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"N value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(passwordString, {"N":1});
	} catch (err) {
		t.ok(err, "Synchronout test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has one property, only N (but r and p are also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	
	try {
		scrypt.passwordHash(passwordString, {"N":1}, function(){});
	} catch (err) {
		t.ok(err, "Asychronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has one property, only N (but r and p are also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(passwordString, {"N":1,"r":1});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because the scrypt parameter object is malformed - in this case, it has two properties, only N and r (but p is also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"p value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(passwordString, {"N":1,"r":1}, function() {});
	} catch (err) {
		t.ok(err, "Asyncrhonous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has two properties, only N and r (but p is also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"p value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(passwordString, {"N":1,"p":1});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has two properties, only N and p (but r is also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(passwordString, {"N":1,"p":1}, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has two properties, only N and p (but r is also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(passwordString, {"N":"hello","r":1, "p":1});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, N type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"N must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(passwordString, {"N":"hello","r":1, "p":1},function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, N type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"N must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(passwordString, {"N":1,"r":"hello", "p":1});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, r type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(passwordString, {"N":1,"r":"hello", "p":1}, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, r type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(passwordString, {"N":1,"r":1, "p":"hello"});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, p type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"p must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(passwordString, {"N":1,"r":1, "p":"hello"}, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, p type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"p must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - maxtime not a number", function(t) {
	try {
		scrypt.passwordHash(passwordString, "hello world");
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, p type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(JSARG,"expecting maxtime as a number"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(passwordString, "hello world", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, p type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(JSARG,"expecting maxtime as a number"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - password string is empty", function(t) {
	try {
		scrypt.passwordHash("", scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the password string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash("", scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the password string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - password string object is empty", function(t) {
	try {
		scrypt.passwordHash(new String(""), scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the password string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(new String(""), scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the password string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - password buffer is empty", function(t) {
	try {
		scrypt.passwordHash(new Buffer(""), scryptParameters);
	} catch (err) {
		t.ok(err, "synchronous test: an error was correctly thrown because the password string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(new Buffer(""), scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the password string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - only two arguments present, password and callback function" , function(t) {
	try {
		scrypt.passwordHash(passwordString, function(){});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because there was no scrypt parameters object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"wrong number of arguments at least two arguments are needed before the callback function - password and scrypt parameters JSON object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

//Synchronous
test("Password Hash (Synchronous): hash password with correct arguments: password string and scrypt parameters object", function(t) {
	var hash = scrypt.passwordHash(passwordString, scryptParameters);
	t.ok(true, "The password was hashed successfully, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash password with correct arguments: password string and maxtime number", function(t) {
	var hash = scrypt.passwordHash(passwordString, 1);
	t.ok(true, "The password was hashed successfully, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash password with correct arguments: password string, maxtime number and maxmem number", function(t) {
	var hash = scrypt.passwordHash(passwordString, 1, 0.05);
	t.ok(true, "The password was hashed successfully, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash password with correct arguments: password string,maxtime number, maxmemnumber and maxmem_frac number", function(t) {
	var hash = scrypt.passwordHash(passwordString, 1, 0.05, 0.05);
	t.ok(true, "The password was hashed successfully, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash password with correct arguments: password string object and scrypt parameters object", function(t) {
	var hash = scrypt.passwordHash(passwordStringObject, scryptParameters);
	t.ok(true, "The password was hashed successfully with a string object, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash password with correct arguments: password buffer and scrypt parameters object", function(t) {
	var hash = scrypt.passwordHash(passwordBuffer, scryptParameters);
	t.ok(true, "The password was hashed successfully with a buffer, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash password with correct arguments: password string and scrypt parameters object, but expecting a buffer to be returned", function(t) {
	var hash = scrypt.passwordHash(passwordString, scryptParameters, true);
	t.ok(true, "The password was hashed successfully, as expected");
	t.ok(Buffer.isBuffer(hash), "The hash that was returned is of type 'Buffer', as expected because it was specified that a buffer must be returned");
	t.end();
});

test("Password Hash (Synchronous): hash password with correct arguments: password string and scrypt parameters object, but buffer value given of type 'string'", function(t) {
	var hash = scrypt.passwordHash(passwordString, scryptParameters, "this will work");
	t.ok(true, "The password was hashed successfully, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because a 'true' value could not be ascertained for buffer, so it assumed it was set to false)");
	t.end();
});

//Asynchronous
test("Password Hash (Asynchronous): hash password with correct arguments: password string and scrypt parameters object", function(t) {
	scrypt.passwordHash(passwordString, scryptParameters, function(err, hash) {
		t.ok(true, "The password was hashed successfully, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash password with correct arguments: password string and maxtime number", function(t) {
	scrypt.passwordHash(passwordString, 1, function(err, hash) {
		t.ok(true, "The password was hashed successfully, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Aynchronous): hash password with correct arguments: password string, maxtime number and maxmem number", function(t) {
	scrypt.passwordHash(passwordString, 1, 0.05, function(err, hash) {
		t.ok(true, "The password was hashed successfully, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash password with correct arguments: password string,maxtime number, maxmemnumber and maxmem_frac number", function(t) {
	scrypt.passwordHash(passwordString, 1, 0.05, 0.05, function(err, hash) {
		t.ok(true, "The password was hashed successfully, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash password with correct arguments: password string object and scrypt parameters object", function(t) {
	scrypt.passwordHash(passwordStringObject, scryptParameters, function(err, hash) {
		t.ok(true, "The password was hashed successfully with a string object, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash password with correct arguments: password buffer and scrypt parameters object", function(t) {
	scrypt.passwordHash(passwordBuffer, scryptParameters,function (err, hash) {
		t.ok(true, "The password was hashed successfully with a buffer, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash password with correct arguments: password string and scrypt parameters object, but expecting a buffer to be returned", function(t) {
	scrypt.passwordHash(passwordString, scryptParameters, true, function(err, hash) {
		t.ok(true, "The password was hashed successfully, as expected");
		t.ok(Buffer.isBuffer(hash), "The hash that was returned is of type 'Buffer', as expected because it was specified that a buffer must be returned");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash password with correct arguments: password string and scrypt parameters object, but buffer value given of type 'string'", function(t) {
	scrypt.passwordHash(passwordString, scryptParameters, "this should work", function(err, hash) {
		t.ok(true, "The password was hashed successfully, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because a 'true' value could not be ascertained for buffer, so it assumed it was set to false)");
		t.end();
	});
});


//
// Password Verify
//
test("Password Verify: incorrect arguments - no arguments present", function(t) {
	try {
		scrypt.verifyHash();
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least two arguments are needed - in this case, no arguments were given");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"both hash and password are needed"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect arguments - one argument present", function(t) {
	try {
		scrypt.verifyHash("hash");
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least two arguments are needed - in this case, no arguments were given");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"both hash and password are needed"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - two arguments present, but one of them is a callback", function(t) {
	try {
		scrypt.verifyHash("hash", function(){});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least two arguments are needed - in this case, no arguments were given");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"both hash and password are needed before the callback function"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - hash not a string nor a string object nor a buffer", function(t) {
	try {
		scrypt.verifyHash(123, "string");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, hash is a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash must be a string or a buffer"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash(123, "string", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, hash is a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash must be a string or a buffer"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - hash is an object, but not a buffer nor a string object", function(t) {
	try {
		scrypt.verifyHash({}, "string");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, hash is an empty JSON object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash must be a buffer or string object"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash({}, "string", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, hash is an empty JSON object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash must be a buffer or string object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - hash an empty string", function(t) {
	try {
		scrypt.verifyHash("", passwordString);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the hash string is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("", "string", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the hash string is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - hash an empty string object", function(t) {
	try {
		scrypt.verifyHash(new String(""), passwordString);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the hash string object is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash(new String(""), "string", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the hash string object is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - hash an empty buffer", function(t) {
	try {
		scrypt.verifyHash(new Buffer(""), "string");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the hash buffer is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash(new Buffer(""), "string", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the hash buffer is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - password not a string nor a string object nor a buffer", function(t) {
	try {
		scrypt.verifyHash("hash", 123);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because password is not a recognised type, namely string, string object or buffer. In this case, password is a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password must be a string or a buffer"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", 123, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because password is not a recognised type, namely string, string object or buffer. In this case, password is a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password must be a string or a buffer"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - password is an object, but not a buffer nor a string object", function(t) {
	try {
		scrypt.verifyHash("hash",{});
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because password is not a recognised type, namely string, string object or buffer. In this case, password is an empty JSON object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password must be a buffer or string object"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", {}, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, password is an empty JSON object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password must be a buffer or string object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - password an empty string", function(t) {
	try {
		scrypt.verifyHash("hash", "");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the password string is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", "", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the password string is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - password an empty string object", function(t) {
	try {
		scrypt.verifyHash("hash", new String(""));
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the password string object is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", new String(""), function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the password string object is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - password an empty buffer", function(t) {
	try {
		scrypt.verifyHash("hash", new Buffer(""));
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the password buffer is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", new Buffer(""), function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the password buffer is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"password cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});


//
// Scrypt KDF Tests
//
test("Scrypt KDF: Incorrect arguments - no arguments present", function(t) {
	try {
		scrypt.KDF();
	} catch (err) {
		t.ok(err, "An error was correctly thrown because there were no arguments present");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"at least two arguments are needed - key and a json object representing the scrypt parameters"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - callback in incorrect position", function(t) {
	try {
		scrypt.KDF("string",function(){});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because the callback function preceeded other needed arguments");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"at least two arguments are needed before the callback function - key and a json object representing the scrypt parameters"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - key is not of type string, string object nor buffer", function(t) {
	try {
		scrypt.KDF(123, scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or a string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.KDF(123, scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or a string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - key is an object, not a string object nor a buffer", function(t) {
	try {
		scrypt.KDF({}, scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or a string object"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.KDF({}, scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or a string object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - scrypt parameters is not an object", function(t) {
	try {
		scrypt.KDF("key", 123);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the scrypt parameters JSON object is passed as a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"expecting JSON object representing scrypt parameters"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.KDF("key", 123, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the scrypt parameters JSON object is passed as a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"expecting JSON object representing scrypt parameters"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - length is not a number", function(t) {
	try {
		scrypt.KDF("key", scryptParameters, "this should be a number");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the length parameter was of type string");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"length must be a number"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.KDF("key", scryptParameters, "this should be a number", function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the length parameter was of type string");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"length must be a number"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - salt is not of type string, string object nor buffer", function(t) {
	try {
		scrypt.KDF("key", scryptParameters, 32, 123);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"salt must be a buffer or a string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.KDF("key", scryptParameters, 32, 123, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"salt must be a buffer or a string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - salt is an object, but not a string object nor a buffer", function(t) {
	try {
		scrypt.KDF("key", scryptParameters, 32, {});
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"salt must be a buffer or string object"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.KDF("key", scryptParameters, 32, {}, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"salt must be a buffer or string object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});
/*
test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
/*
test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash("password", {});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because the scrypt parameter object is malformed - in this case, it is an empty object");
		t.deepEqual(err,scrypt.errorObject(2,"N value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});*/
//Asynchronous
/*test("Asynchronous: Password hashing with incorrect arguments - only two arguments present", function(t) {
    console.log("Password Hash Functionality\nTesting of arguments\n");
    try {
        scrypt.passwordHash(maxtime_passwordhash, function(err, hash) {} );
    } catch (err) {
        t.ok(err,"An error was correctly thrown because either password, max_time or callback not present - in this case, password was not present");
        t.equal(err.message,"Wrong number of arguments: At least two arguments are needed before the callback function - password and max_time", "The correct object is returned, namely: "+err.message);
        t.end();
    }
});

test("Asynchronous: Password hashing with incorrect arguments - only two arguments present", function(t) {
    try {
        scrypt.passwordHash(password, function(err, hash) {} );
    } catch (err) {
        t.ok(err,"An error was correctly thrown because either password, max_time or callback not present - in this case, maxtime_passwordhash was not present");
        t.equal(err.message,"Wrong number of arguments: At least two arguments are needed before the callback function - password and max_time", "The correct object is returned, namely: "+err.message);
        t.end();
    }
});

test("Asynchronous: Password hashing with incorrect arguments - password given an argument that is not a string", function(t) {
    try {
        scrypt.passwordHash(1232, maxtime_passwordhash, function(err, hash) {
        })
    } catch (err) {
        t.ok(err,"An error was correctly thrown because password was not set as a string (it was set as 1232)");
        t.equal(err.message,"password must be a string", "The correct object is returned, namely: "+err.message);
        t.end();
    }
});

test("Asynchronous: Password hashing with incorrect arguments - maxtime given an argument that is not a number", function(t) {
    try {
        scrypt.passwordHash(password, 'a', function(err, hash) {
        })
    } catch (err) {
        t.ok(err,"An error was correctly thrown because maxtime was not set as a number (it was set as 'a')");
        t.equal(err.message,"maxtime argument must be a number", "The correct object is returned, namely: "+err.message);
        t.end();
    }
});

test("Asynchronous: Password hashing and verifying: Same password verify and hash (Result Must Be True)", function(t) {
    console.log("\nPassword Hash Functionality\nTesting of hashing functionality\n");
    scrypt.passwordHash(password, maxtime_passwordhash, function(err, hash) {
        t.notOk(err,'No error hashing password');
        scrypt.verifyHash(hash, password, function(err, result) {
            t.notOk(err,'No error verifying hash');
            t.equal(result, true,'Hash has been verified as true => Result Is True');
            t.end();
        })
    })
});

test("Asynchronous: Password hashing and verifying: Different password verify and hash (Result Must Be False)", function(t) {
    scrypt.passwordHash(password, maxtime_passwordhash, function(err, hash) {
        t.notOk(err,'No error hashing password');
        scrypt.verifyHash(hash, "Another password", function(err, result) {
            t.ok(err,'Verification of hash failed because different passwords used');
            t.equal(result, false,'Hash has not been verified => Result Is False');
            t.end();
        })
    })
});

test("Asynchronous: Password hashing: Salt means same passwords hash to different values", function(t) {
    scrypt.passwordHash(password, maxtime_passwordhash, function(err, hash1) {
        scrypt.passwordHash(password, maxtime_passwordhash, function(err, hash2) {
            t.notEqual(hash1,hash2,"Same passwords are correctly hashed to different values due to salt");
            t.end();
        })
    })
});


//Synchronous
test("Synchronous: Password hashing with incorrect arguments - only two arguments present", function(t) {
    console.log("Password Hash Functionality\nTesting of arguments\n");
    try {
        scrypt.passwordHashSync(maxtime_passwordhash);
    } catch (err) {
        t.ok(err,"An error was correctly thrown because either password, max_time or callback not present - in this case, password was not present");
        t.equal(err.message,"Wrong number of arguments: At least two arguments are needed - password and max_time", "The correct object is returned, namely: "+err.message);
        t.end();
    }
});

test("Synchronous: Password hashing with incorrect arguments - only two arguments present", function(t) {
    console.log("Password Hash Functionality\nTesting of arguments\n");
    try {
        scrypt.passwordHashSync(maxtime_passwordhash);
    } catch (err) {
        t.ok(err,"An error was correctly thrown because either password or max_time not present - in this case, password was not present");
        t.equal(err.message,"Wrong number of arguments: At least two arguments are needed - password and max_time", "The correct object is returned, namely: "+err.message);
        t.end();
    }
});

test("Synchronous: Password hashing with incorrect arguments - only two arguments present", function(t) {
    try {
        scrypt.passwordHashSync(password);
    } catch (err) {
        t.ok(err,"An error was correctly thrown because either password, max_time not present - in this case, maxtime was not present");
        t.equal(err.message,"Wrong number of arguments: At least two arguments are needed - password and max_time", "The correct object is returned, namely: "+err.message);
        t.end();
    }
});


test("Synchronous: Password hashing with incorrect arguments - password given an argument that is not a string", function(t) {
    try {
        scrypt.passwordHashSync(1232, maxtime_passwordhash);
    } catch (err) {
        t.ok(err,"An error was correctly thrown because password was not set as a string (it was set as 1232)");
        t.equal(err.message,"password must be a string", "The correct object is returned, namely: "+err.message);
        t.end();
    }
});

test("Synchronous: Password hashing with incorrect arguments - maxtime given an argument that is not a number", function(t) {
    try {
        scrypt.passwordHashSync(password, 'a');
    } catch (err) {
        t.ok(err,"An error was correctly thrown because maxtime was not set as a number (it was set as 'a')");
        t.equal(err.message,"maxtime argument must be a number", "The correct object is returned, namely: "+err.message);
        t.end();
    }
});

test("Synchronous: Password hashing and verifying: Same password verify and hash (Result Must Be True)", function(t) {
    console.log("\nPassword Hash Functionality\nTesting of hashing functionality\n");
    var hash = scrypt.passwordHashSync(password, maxtime_passwordhash);
    var result = scrypt.verifyHashSync(hash, password);
    t.equal(result, true,'Hash has been verified as true => Result Is True');
    t.end();
});

test("Synchronous: Password hashing and verifying: Different password verify and hash (Result Must Be False)", function(t) {
    var hash = scrypt.passwordHashSync(password, maxtime_passwordhash);
    var result = scrypt.verifyHashSync(hash, "Another password");
    t.equal(result, false,'Hash has not been verified => Result Is False');
    t.end();
});

test("Synchronous: Password hashing: Salt means same passwords hash to different values", function(t) {
    var hash1 = scrypt.passwordHashSync(password, maxtime_passwordhash);
    var hash2 = scrypt.passwordHashSync(password, maxtime_passwordhash);
    t.notEqual(hash1,hash2,"Same passwords are correctly hashed to different values due to salt");
    t.end();
});*/
