var test = require('tap').test;
var scrypt = require('../');
var password = "This is the test password";
var maxtime_passwordhash = 0.05; 
var message = "This is a message";
var scryptParams = {"N":1, "r":1, "p":1}

//
// Translation Function (Parameter) Tests */
//

//General (applies to both async and sync)
test("Pick Parameters (Translation function): - no arguments are present", function(t) {
	try {
		scrypt.params();
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least argument is needed - in this case, no arguments were given");
		t.deepEqual(err, scrypt.errorObject(2, "Wrong number of arguments: At least one argument is needed - the maxtime"), "The correct message object is returned, namely:"+ JSON.stringify(err));
		t.end();
	}
});

test("Pick Parameters (Translation function): incorrect argument type", function(t) {
	try {
		scrypt.params("abc");
	} catch (err) {
		t.ok(err, "An error was correctly thrown because an incorrect type was passed to the function - in this case, the maxtime was passed as a string, but a number is expected");
		t.deepEqual(err,scrypt.errorObject(2,"maxtime argument must be a number"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Pick Parameters (Translation function): incorrect argument type", function(t) {
	try {
		scrypt.params(0);
	} catch (err) {
		t.ok(err, "An error was correctly thrown because maxtime was passed as a number <= 0");
		t.deepEqual(err, scrypt.errorObject(2, "maxtime must be greater than 0"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Pick Parameters (Translation function): incorrect argument type", function(t) {
	try {
		scrypt.params(1, "abc");
	} catch (err) {
		t.ok(err, "An error was correctly thrown because an incorrect type was passed to the function - in this case, the maxmem was passed as a string, but a number is expected");
		t.deepEqual(err,scrypt.errorObject(2, "maxmem argument must be a number"), "The correct object is returned, namely: "+ JSON.stringify(err));
		t.end();
	}
});

test("Pick Parameters (Translation function): incorrect argument type", function(t) {
	try {
		scrypt.params(1, 0.5, "abc");
	} catch (err) {
		t.ok(err, "An error was correctly thrown because an incorrect type was passed to the function - in this case, the maxmemfrac was passed as a string, but a number is expected");
		t.deepEqual(err, scrypt.errorObject(2, "max_memfrac argument must be a number"), "The correct object is returned, namely: " + JSON.stringify(err.message));
		t.end();
	}
});

//Asynchronous
test("Pick Parameters (Asynchronous): incorrect argument - no arguments before callback", function(t) {
	try {
		scrypt.params(function(){});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least argument is needed before the callback - in this case, no arguments were given");
		t.deepEqual(err,scrypt.errorObject(2,"Wrong number of arguments: At least one argument is needed before the callback - the maxtime"), "The correct object is returned, namely: " + JSON.stringify(err));
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
		t.deepEqual(err,scrypt.errorObject(2,"Wrong number of arguments: At least two arguments are needed - password and scrypt parameters JSON object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - only one argument present", function(t) {
	try {
		scrypt.passwordHash(password);
	} catch (err) {
		t.ok(err, "An error was correctly thrown because at one least two arguments are needed - in this case, only one was present, namely the password");
		t.deepEqual(err,scrypt.errorObject(2,"Wrong number of arguments: At least two arguments are needed - password and scrypt parameters JSON object"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected password is not a string", function(t) {
	try {
		scrypt.passwordHash(1232, scryptParams);
	} catch (err) {
		t.ok(err, "An error was correctly thrown because the password type was incorrect - in this case, it was of type number, but it should be of type string or buffer");
		t.deepEqual(err,scrypt.errorObject(2,"password must be a buffer or a string"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash("password", {});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because the scrypt parameter object is malformed - in this case, it is an empty object");
		t.deepEqual(err,scrypt.errorObject(2,"N value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash("password", {"N":1});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because the scrypt parameter object is malformed - in this case, it has one property, only N (but r and p are also needed)");
		t.deepEqual(err,scrypt.errorObject(2,"r value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

test("Password Hash: incorrect arguments - expected scrypt parameter object is malformed", function(t) {
	try {
		scrypt.passwordHash("password", {"N":1,"r":1});
	} catch (err) {
		t.ok(err, "An error was correctly thrown because the scrypt parameter object is malformed - in this case, it has two properties, only N and r (but p is also needed)");
		t.deepEqual(err,scrypt.errorObject(2,"p value is not present"), "The correct object is returned, namely: " + JSON.stringify(err));
		t.end();
	}
});

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
