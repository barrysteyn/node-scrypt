var test = require('tap').test;
var scrypt = require('../');
var keyString = "This is the test key";
var keyStringObject = new String(keyString);
var keyBuffer = new Buffer(keyString);
var message = "This is a message";
var scryptParameters = {"N":1, "r":1, "p":1}

//These error results are taken verbatim from src/node-boilerplate/scrypt_common.h
var JSARG=1; //Error in JavaScript land: Argument mismatch
var ADDONARG=2; //Error resulting from argument mismatch in the node addon module
var PARMOBJ=3; //Scrypt generated errors
var SCRYPT=4; //Scrypt generated errors

//
// Logic Tests
// 
test("KDF - Test vector 1", function(t) {
	var kdf = scrypt.KDF();
	kdf.config.saltEncoding = "ascii";
	var buf = new Buffer("");
	var res = kdf(buf,{"N":16,"r":1,"p":1},64,"");
	t.equal(res.hash.toString("hex"),"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906","Synchronous test: first test vector is correctly returned");	

	kdf(buf, {"N":16,"r":1,"p":1},64,"", function(err, res) {
		t.equal(res.hash.toString("hex"),"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906","Asynchronous test: first test vector is correctly returned");
		t.end();
	});
});

test("KDF - Test vector 2", function(t) {
	var kdf = scrypt.KDF();
	kdf.config.keyEncoding = "ascii";
	var buf = new Buffer("NaCl");
	var res = kdf("password",{"N":1024,"r":8,"p":16},64,buf);
	t.equal(res.hash.toString("hex"),"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640","Synchronous test: second test vector is correctly returned");	

	kdf("password", {"N":1024,"r":8,"p":16},64,buf, function(err, res) {
		t.equal(res.hash.toString("hex"),"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640","Synchronous test: second test vector is correctly returned");	
		t.end();
	});
});

test("KDF - Test vector 3", function(t) {
	var kdf = scrypt.KDF();
	kdf.config.outputEncoding = "hex";
	var buf = new Buffer("pleaseletmein");
	var salt = new Buffer("SodiumChloride");
	var res = kdf(buf,{"N":16384,"r":8,"p":1},64,salt);
	t.equal(res.hash, "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887","Synchronous test: third test vector is correctly returned");	

	kdf(buf, {"N":16384,"r":8,"p":1},64,salt, function(err, res) {
		t.equal(res.hash,"7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887","Asynchronous test: third test vector is correctly returned");
		t.end();
	});
});

//test("KDF - Test vector 4", function(t) { //This test takes too long to perform for continuous integration
//	var res = scrypt.kdf("pleaseletmein",{"N":1048576,"r":8,"p":1},64,"SodiumChloride");
//	t.equal(res.hash.toString("hex"),"2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4", "Synchronous test: fourth test vector is correctly returned");	
//
//	scrypt.kdf("pleaseletmein", {"N":1048576,"r":8,"p":1},64,"SodiumChloride", function(err, res) {
//		t.equal(res.hash.toString("hex"),"2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4","Asynchronous test: fourth test vector is correctly returned");
//		t.end();
//	});
//});

test("KDF - Random salt added by default", function(t) {
	var key = new Buffer("key");	
	var hash1 = scrypt.kdf(key, scryptParameters);
	var hash2 = scrypt.kdf(key, scryptParameters);
	t.notEqual(hash1.hash.toString(), hash2.hash.toString(), "Synchronous: hashes that are returned are not equal. This is correct due to random salt that was added");
	t.notEqual(hash1.salt.toString(), hash2.salt.toString(), "Synchronous: salts that are returned are not equal");

	scrypt.kdf(key, scryptParameters, function(err, hash1) {
		scrypt.kdf(key, scryptParameters, function(err, hash2) {
			t.notEqual(hash1.hash.toString(), hash2.hash.toString(), "Asynchronous: hashes that are returned are not equal. This is correct due to random salt that was added");
			t.notEqual(hash1.salt.toString(), hash2.salt.toString(), "Asynchronous: salts that are returned are not equal");
			t.end();
		});
	});
});

test("KDF - Deterministic non-random salt added manually", function(t) {
	var key = new Buffer("key");
	var salt = new Buffer("salt");	
	var hash1 = scrypt.kdf(key, scryptParameters, 64, salt);
	var hash2 = scrypt.kdf(key, scryptParameters, 64, salt);
	t.equal(hash1.hash.toString(), hash2.hash.toString(), "Synchronous: hashes that are returned are equal. This is correct due to non-random salt that was added");
	t.equal(hash1.salt.toString(), hash2.salt.toString(), "Synchronous: salts that are returned are identical");

	scrypt.kdf(key, scryptParameters, 64, salt, function(err, hash1) {
		scrypt.kdf(key, scryptParameters, 64, salt, function(err, hash2) {
			t.equal(hash1.hash.toString(), hash2.hash.toString(), "Asynchronous: hashes that are returned are equal. This is correct due to non-random salt that was added");
			t.equal(hash1.salt.toString(), hash2.salt.toString(), "Asynchronous: salts that are returned are identical");
			t.end();
		});
	});
});

test("Password hashing: Salt means same keys hash to different values", function(t) {
    var hash1 = scrypt.passwordHashSync(keyString, scryptParameters);
    var hash2 = scrypt.passwordHashSync(keyString, scryptParameters);
    t.notEqual(hash1,hash2,"Synchronous: same keys are correctly hashed to different values due to salt");
	
	scrypt.passwordHash(keyString, scryptParameters, function(err, hash1) {
		scrypt.passwordHash(keyString, scryptParameters, function(err, hash2) {
			t.notEqual(hash1,hash2,"Asynchronous: same keys are correctly hashed to different values due to salt");
			t.end();
		});
	});
});

test("Password hashing and verifying: Same key verify and hash (Consistency test - Result Must Be True)", function(t) {
	hash = scrypt.passwordHash(keyString, scryptParameters);
	result = scrypt.verifyHash(hash, keyString);
	t.equal(result, true,"Synchronous: hash has been verified as true => Result Is True");

    scrypt.passwordHash(keyString, scryptParameters, function(err, hash) {
		t.notOk(err,"Asynchronous: no error hashing result");
        scrypt.verifyHash(hash, keyString, function(err, result) {
            t.notOk(err,"Asynchronous: no error verifying hash");
            t.equal(result, true,"Asynchronous: hash has been verified as true => Result Is True");
            t.end();
        })
    })
});

test("Password hashing and verifying: Different keys do not verify (Result Must Be False)", function(t) {
	hash = scrypt.passwordHash(keyString, scryptParameters);
	result = scrypt.verifyHash(hash, "another key");
	t.equal(result, false,"Synchronous: hash has been verified as false => Result Is False (as it should be)");

    scrypt.passwordHash(keyString, scryptParameters, function(err, hash) {
		t.notOk(err,"Asynchronous: no error hashing result");
        scrypt.verifyHash(hash, "another key", function(err, result) {
            t.ok(err,"Asynchronous: error verifying hash - because hashes are not the same (as expected)");
            t.equal(result, false,"Asynchronous: hash has been verified as false => Result Is False (as it should be)");
            t.end();
        })
    })
});

//
//  Argument Tests
//


//
// Translation Function (Parameter) Tests 
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
		t.deepEqual(err,scrypt.errorObject(JSARG,"wrong number of arguments - at least two arguments are needed - key and scrypt parameters JSON object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - only one argument present", function(t) {
	try {
		scrypt.passwordHash(keyString);
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least two arguments are needed - in this case, only one was present, namely the key");
		t.deepEqual(err,scrypt.errorObject(JSARG,"wrong number of arguments - at least two arguments are needed - key and scrypt parameters JSON object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected key is not a string", function(t) {
	try {
		scrypt.passwordHash(1232, scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test: An error was correctly thrown because the key type was incorrect - in this case, it was of type number, but it should be of type string or buffer");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	
	try {
		scrypt.passwordHash(1232, scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: An error was correctly thrown because the key type was incorrect - in this case, it was of type number, but it should be of type string or buffer");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(keyString, {});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it is an empty object");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"N value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	
	try {
		scrypt.passwordHash(keyString, {}, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it is an empty object");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"N value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(keyString, {"N":1});
	} catch (err) {
		t.ok(err, "Synchronout test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has one property, only N (but r and p are also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	
	try {
		scrypt.passwordHash(keyString, {"N":1}, function(){});
	} catch (err) {
		t.ok(err, "Asychronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has one property, only N (but r and p are also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(keyString, {"N":1,"r":1});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because the scrypt parameter object is malformed - in this case, it has two properties, only N and r (but p is also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"p value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(keyString, {"N":1,"r":1}, function() {});
	} catch (err) {
		t.ok(err, "Asyncrhonous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has two properties, only N and r (but p is also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"p value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(keyString, {"N":1,"p":1});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has two properties, only N and p (but r is also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(keyString, {"N":1,"p":1}, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, it has two properties, only N and p (but r is also needed)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(keyString, {"N":"hello","r":1, "p":1});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, N type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"N must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(keyString, {"N":"hello","r":1, "p":1},function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, N type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"N must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(keyString, {"N":1,"r":"hello", "p":1});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, r type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(keyString, {"N":1,"r":"hello", "p":1}, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, r type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"r must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash(keyString, {"N":1,"r":1, "p":"hello"});
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, p type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"p must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(keyString, {"N":1,"r":1, "p":"hello"}, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, p type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(PARMOBJ,"p must be a numeric value"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - maxtime not a number", function(t) {
	try {
		scrypt.passwordHash(keyString, "hello world");
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, p type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(JSARG,"expecting maxtime as a number"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(keyString, "hello world", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the scrypt parameter object is malformed - in this case, p type is a string (it should be a numeric)");
		t.deepEqual(err,scrypt.errorObject(JSARG,"expecting maxtime as a number"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - key string is empty", function(t) {
	try {
		scrypt.passwordHash("", scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the key string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash("", scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the key string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - key string object is empty", function(t) {
	try {
		scrypt.passwordHash(new String(""), scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test: an error was correctly thrown because the key string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(new String(""), scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the key string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - key buffer is empty", function(t) {
	try {
		scrypt.passwordHash(new Buffer(""), scryptParameters);
	} catch (err) {
		t.ok(err, "synchronous test: an error was correctly thrown because the key string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}
	try {
		scrypt.passwordHash(new Buffer(""), scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test: an error was correctly thrown because the key string was empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - only two arguments present, key and callback function" , function(t) {
	try {
		scrypt.passwordHash(keyString, function(){});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because there was no scrypt parameters object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"wrong number of arguments at least two arguments are needed before the callback function - key and scrypt parameters JSON object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

//Synchronous
test("Password Hash (Synchronous): hash key with correct arguments: key string and scrypt parameters object", function(t) {
	var hash = scrypt.passwordHash(keyString, scryptParameters);
	t.ok(true, "The key was hashed successfully, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash key with correct arguments: key string and maxtime number", function(t) {
	var hash = scrypt.passwordHash(keyString, 1);
	t.ok(true, "The key was hashed successfully, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash key with correct arguments: key string, maxtime number and maxmem number", function(t) {
	var hash = scrypt.passwordHash(keyString, 1, 0.05);
	t.ok(true, "The key was hashed successfully, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash key with correct arguments: key string,maxtime number, maxmemnumber and maxmem_frac number", function(t) {
	var hash = scrypt.passwordHash(keyString, 1, 0.05, 0.05);
	t.ok(true, "The key was hashed successfully, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash key with correct arguments: key string object and scrypt parameters object", function(t) {
	var hash = scrypt.passwordHash(keyStringObject, scryptParameters);
	t.ok(true, "The key was hashed successfully with a string object, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});

test("Password Hash (Synchronous): hash key with correct arguments: key buffer and scrypt parameters object", function(t) {
	var hash = scrypt.passwordHash(keyBuffer, scryptParameters);
	t.ok(true, "The key was hashed successfully with a buffer, as expected");
	t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
	t.end();
});


//Asynchronous
test("Password Hash (Asynchronous): hash key with correct arguments: key string and scrypt parameters object", function(t) {
	scrypt.passwordHash(keyString, scryptParameters, function(err, hash) {
		t.ok(true, "The key was hashed successfully, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash key with correct arguments: key string and maxtime number", function(t) {
	scrypt.passwordHash(keyString, 1, function(err, hash) {
		t.ok(true, "The key was hashed successfully, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Aynchronous): hash key with correct arguments: key string, maxtime number and maxmem number", function(t) {
	scrypt.passwordHash(keyString, 1, 0.05, function(err, hash) {
		t.ok(true, "The key was hashed successfully, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash key with correct arguments: key string,maxtime number, maxmemnumber and maxmem_frac number", function(t) {
	scrypt.passwordHash(keyString, 1, 0.05, 0.05, function(err, hash) {
		t.ok(true, "The key was hashed successfully, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash key with correct arguments: key string object and scrypt parameters object", function(t) {
	scrypt.passwordHash(keyStringObject, scryptParameters, function(err, hash) {
		t.ok(true, "The key was hashed successfully with a string object, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
		t.end();
	});
});

test("Password Hash (Asynchronous): hash key with correct arguments: key buffer and scrypt parameters object", function(t) {
	scrypt.passwordHash(keyBuffer, scryptParameters,function (err, hash) {
		t.ok(true, "The key was hashed successfully with a buffer, as expected");
		t.type(hash, "string", "The hash that was returned is of type 'string', as expected (because it is base64 encoded)");
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
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"both hash and key are needed"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect arguments - one argument present", function(t) {
	try {
		scrypt.verifyHash("hash");
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least two arguments are needed - in this case, no arguments were given");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"both hash and key are needed"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - two arguments present, but one of them is a callback", function(t) {
	try {
		scrypt.verifyHash("hash", function(){});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least two arguments are needed - in this case, no arguments were given");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"both hash and key are needed before the callback function"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - hash not a string nor a string object nor a buffer", function(t) {
	try {
		scrypt.verifyHash(123, "string");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, hash is a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash(123, "string", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, hash is a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - hash is an object, but not a buffer nor a string object", function(t) {
	try {
		scrypt.verifyHash({}, "string");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, hash is an empty JSON object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash({}, "string", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, hash is an empty JSON object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"hash must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - hash an empty string", function(t) {
	try {
		scrypt.verifyHash("", keyString);
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
		scrypt.verifyHash(new String(""), keyString);
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

test("Password Verify: incorrect argument type - key not a string nor a string object nor a buffer", function(t) {
	try {
		scrypt.verifyHash("hash", 123);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because key is not a recognised type, namely string, string object or buffer. In this case, key is a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", 123, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because key is not a recognised type, namely string, string object or buffer. In this case, key is a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - key is an object, but not a buffer nor a string object", function(t) {
	try {
		scrypt.verifyHash("hash",{});
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because key is not a recognised type, namely string, string object or buffer. In this case, key is an empty JSON object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", {}, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because hash is not a recognised type, namely string, string object or buffer. In this case, key is an empty JSON object");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - key an empty string", function(t) {
	try {
		scrypt.verifyHash("hash", "");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the key string is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", "", function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the key string is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - key an empty string object", function(t) {
	try {
		scrypt.verifyHash("hash", new String(""));
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the key string object is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", new String(""), function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the key string object is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Verify: incorrect argument type - key an empty buffer", function(t) {
	try {
		scrypt.verifyHash("hash", new Buffer(""));
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the key buffer is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.verifyHash("hash", new Buffer(""), function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the key buffer is empty");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key cannot be empty"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});


//
// Scrypt KDF Tests
//
test("Scrypt KDF: Incorrect arguments - no arguments present", function(t) {
	try {
		scrypt.kdf();
	} catch (err) {
		t.ok(err, "An error was correctly thrown because there were no arguments present");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"at least two arguments are needed - key and a json object representing the scrypt parameters"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - callback in incorrect position", function(t) {
	try {
		scrypt.kdf("string",function(){});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because the callback function preceeded other needed arguments");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"at least two arguments are needed before the callback function - key and a json object representing the scrypt parameters"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - key is not of type string, string object nor buffer", function(t) {
	try {
		scrypt.kdf(123, scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.kdf(123, scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - key is an object, not a string object nor a buffer", function(t) {
	try {
		scrypt.kdf({}, scryptParameters);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		scrypt.kdf({}, scryptParameters, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the key is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"key must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - scrypt parameters is not an object", function(t) {
    var kdf = new scrypt.KDF();
    kdf.config.keyEncoding = "ascii";
	try {
		kdf("key", 123);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the scrypt parameters JSON object is passed as a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"expecting JSON object representing scrypt parameters"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		kdf("key", 123, function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the scrypt parameters JSON object is passed as a number");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"expecting JSON object representing scrypt parameters"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - outputLength is not a number", function(t) {
    var kdf = new scrypt.KDF();
    kdf.config.keyEncoding = "ascii";
	try {
		kdf("key", scryptParameters, "this should be a number");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the size parameter was of type string");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"outputLength must be a number"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		kdf("key", scryptParameters, "this should be a number", function() {});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the size parameter was of type string");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"outputLength must be a number"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - salt is not of type string, string object nor buffer", function(t) {
    var kdf = new scrypt.KDF();
    kdf.config.keyEncoding = "ascii";
	try {
		kdf("key", scryptParameters, 32, 123);
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the salt is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"salt must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		kdf("key", scryptParameters, 32, 123, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the salt is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"salt must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - salt is an object, but not a string object nor a buffer", function(t) {
	try {
        var kdf = new scrypt.KDF();
        kdf.config.keyEncoding = "ascii";
		kdf("key", scryptParameters, 32, {});
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the salt is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"salt must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		kdf("key", scryptParameters, 32, {}, function(){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the salt is of an incorrect type");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"salt must be a buffer or string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Scrypt KDF: Incorrect arguments - outputLength is less than or equal to zero", function(t) {
	try {
        var kdf = new scrypt.KDF();
        kdf.config.keyEncoding = "ascii";
		kdf("key", scryptParameters, 0, "");
	} catch (err) {
		t.ok(err, "Synchronous test - An error was correctly thrown because the outputLength was set to zero");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"outputLength must be greater than 0"), "The correct object is returned, namely: " + JSON.stringify(err));
	}

	try {
		kdf("key", scryptParameters, 0, "", function(err, result){});
	} catch (err) {
		t.ok(err, "Asynchronous test - An error was correctly thrown because the outputLength was set to zero");
		t.deepEqual(err,scrypt.errorObject(ADDONARG,"outputLength must be greater than 0"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});
