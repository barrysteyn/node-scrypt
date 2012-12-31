var test = require('tap').test;
var scrypt = require('../build/Release/scrypt');
var password = "This is the test password";
var maxtime = 0.1; //interactive - 100 milliseconds

test("Password hashing with incorrect arguments (Result Must Be True)", function(t) {
    try {
        scrypt.passwordHash(password, 'a', function(err, hash) {
        })
    } catch (err) {
        t.ok(err,"An error was correctly thrown because maxtime was not set as a number (it was set as 'a')");
        t.equal(err.message,"maxtime argument must be a number", "The correct message is displayed, namely: "+err.message);
        t.end();
    }
});

test("Password hashing and verifying: Same password verify and hash (Result Must Be True)", function(t) {
    scrypt.passwordHash(password, maxtime, function(err, hash) {
        t.notOk(err,'No error hashing password');
        scrypt.verifyHash(hash, password, function(err, result) {
            t.notOk(err,'No error verifying hash');
            t.equal(result, true,'Hash has been verified as true => Result Is True');
            t.end();
        })
    })
});

test("Password hashing and verifying: Different password verify and hash (Result Must Be False)", function(t) {
    scrypt.passwordHash(password, maxtime, function(err, hash) {
        t.notOk(err,'No error hashing password');
        scrypt.verifyHash(hash, "Another password", function(err, result) {
            t.ok(err,'Verification of hash failed because different passwords used');
            t.equal(result, false,'Hash has not been verified => Result Is False');
            t.end();
        })
    })
});
