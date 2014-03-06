#Scrypt For NodeJS

[![Build Status](https://travis-ci.org/barrysteyn/node-scrypt.png?branch=master)](https://travis-ci.org/barrysteyn/node-scrypt)

node-scrypt is a native node C++ wrapper for Colin Percival's scrypt utility. 

As should be the case with any security tool, this library should be scrutinized by anyone using it. If you find or suspect an issue with the code- please bring it to my attention and I'll spend some time trying to make sure that this tool is as secure as possible.

##Table Of Contents

 * [Scrypt](#scrypt)
 * [Installation Instructions](#installation-instructions)
 * [Introducing Node-scrypt version 2.X](#introducing-node-scrypt-version-2)
 * [API](#api)
 * [Example Usage](#example-usage)
 * [FAQ](#faq)
 * [Credits](#credits)

##Scrypt
Scrypt is an advanced crypto library used mainly for [key derivation](http://en.wikipedia.org/wiki/Key_derivation_function): More information can be found here:

* [Tarsnap blurb about scrypt](http://www.tarsnap.com/scrypt.html) - Colin Percival (the author of scrypt) explains a bit about it.
* [Academic paper explaining scrypt](http://www.tarsnap.com/scrypt/scrypt.pdf).
* [Wikipedia Article on scrypt](http://en.wikipedia.org/wiki/Scrypt).

##Installation Instructions
###Requirements

 * *node-gyp* 
 * Node version 0.10x (0.11x support coming soon).

####Node-Gyp
[Node-gyp](https://github.com/TooTallNate/node-gyp) is needed to build this module. It should be installed globally, that is, with the `-g` switch:

	npm install -g node-gyp

For operating system specific instructions (like getting *node-gyp* working on Windows), read the official [node-gyp installation instructions](https://github.com/TooTallNate/node-gyp#installation).

###From NPM

    npm install scrypt

###From Source

    git clone https://github.com/barrysteyn/node-scrypt.git
    cd node-scrypt
    node-gyp configure build

###Testing
To test, go to the folder where scrypt was installed, and type:

    npm test

##Introducing Node-Scrypt Version 3
Version 3's main highlight is support for the **Microsoft Windows** platform.

###Node-Scrypt Version 2
Node-Scrypt version 2.0 is a complete rewrite of the previous module. It's main highlights are:


 * Access to the underlying key derivation function
 * Extensive use of node's buffers
 * Easy configuration
 * Removal of scrypt encryption/decryption (this will soon be moved to another module)

The module consists of four functions:

 1. [params](#params) - a translation function that produces scrypt parameters
 2. [hash](#hash) - produces a 256 bit hash using scrypt's key derivation function
 3. [verify](#verify) - verify's a hash produced by this module
 4. [kdf](#key-derivation-function) - scrypt's underlying key dervivation function

It also consists of four extra functions that provide [backward compatibility](#backward-compatibility-for-users-of-version-1x) to the previous version.

####Encodings
The following encodings are accepted:

 1. **ascii**
 2. **utf8**
 3. **base64**
 4. **ucs2** 
 5. **binary**
 6. **hex**
 7. **buffer**

The last encoding is node's [Buffer](http://nodejs.org/api/buffer.html) object. Buffer is useful for representing raw binary data and has the ability to translate into any of the encodings mentioned above. It is for these reasons that encodings default to buffer in this module.

###Params
The [params function](#params-1) translates human understandable parameters to scrypt's internal parameters. 

The human understandable parameters are as follows:

 1. **maxtime**: the maximum amount of time scrypt will spend when computing the derived key.
 2. **maxmemfrac**: the maximum fraction of the available RAM used when computing the derived key.
 3. **maxmem**: the maximum number of bytes of RAM used when computing the derived encryption key. 

Scrypt's internal parameters are as follows:

 1. **N** - general work factor, iteration count.
 2. **r** - blocksize in use for underlying hash; fine-tunes the relative memory-cost.
 3. **p** - parallelization factor; fine-tunes the relative cpu-cost.

For info on what the above parameters do, read [section 5 of the scrypt ietf draft](http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-5).

####How Memory Is Calculated
`maxmem` is often defaulted to `0`. This does not mean that `0` RAM is used. Instead, memory used is calculated like so (quote from Colin Percival):

> the system [will use] the amount of RAM which [is] specified [as the] fraction of the available RAM, but no more than maxmem, and no less than 1MiB

Therefore at the very least, 1MiB of ram will be used.

###Hash
The [hash function](#hash-1) does the following:

 * Adds random salt.
 * Creates a HMAC to protect against active attack.
 * Uses the scrypt key derivation function to derive a hash for a key.

####Hash Format
All hashes start with the word *"scrypt"*. Next comes the scrypt parameters used in the key derivation function, followed by random salt. Finally, a 256 bit HMAC of previous content is appended, with the key for the HMAC being produced by the scrypt key derivation function. The result is a 768 bit (96 byte) output:

 1. **bytes 0-5**: The word *"scrypt"*
 2. **bytes 6-15**: Scrypt parameters N, r, and p
 3. **bytes 16-47**: 32 bits of random salt
 4. **bytes 48-63**: A 16 bit checksum
 5. **bytes 64-95**: A 32 bit HMAC of bytes 0 to 63 using a key produced by the scrypt key derivation function.

Bytes 0 to 63 are left in plaintext. This is necessary as these bytes contain metadata needed for verifying the hash. This information not being encrypted does not mean that security is weakened. What is essential in terms of security is hash **integrity** (meaning that no part of the hashed output can be changed) and that the original password cannot be determined from the hashed output (this is why you are using scrypt - because it does this in a good way). Bytes 64 to 95 is where all this happens.

###Verify
The [verify function](#verify-1) determines whether a hash can be derived from a given key and returns a boolean result.

###Key Derivation Function
The underlying [scrypt key derivation function](#kdf). This functionality is exposed for users who are quite experienced and need the function for business logic. A good example is [litecoin](https://litecoin.org/) which uses the scrypt key derivation function as a proof of work. The key derivation function in this module is tested against [three of the four test vectors](http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00#page-11) in the original scrypt paper. The fourth test vector takes too long to computer and is infeasible to use as testing for continuous integration. Nevertheless, it is included in the tests, but commented out - uncomment it and run the tests, but be warned that it is rather taxing on resources.

####Use Hash To Store Keys
If your interested in this module is to produce hashes to store passwords, then I strongly encourage you to use the hash function. The key derivation function does not produce any [message authentication code](http://en.wikipedia.org/wiki/Message_authentication_code) to ensure integrity. You will also have to store the scrypt parameters separately. Lastly, there is no native verify function included in this module.

In short: If you are going to use this module to store keys, then use the hash function. It has been customized for general key storage and is both easier to use and provides better protection compared to the key derivation function.

###Backward Compatibility For User's Of Version 1.x
Four extra functions are provided for means of backward compatibility:

 1. [passwordHash](#passwordhash)
 2. [passwordHashSync](#passwordhashsync)
 3. [verifyHash](#verifyhash)
 4. [verifyHashSync](#verifyhashsync)

The above functions are defaulted to behave exactly like the previous version.

##API
#####A Note On Error Handling
All synchronous functionality should be wrapped in a `try ... catch` as exceptions are thrown in case of error. For asynchronous functionality, error are returned as the first argument to the callback function if such an error exists. An error is an object with both an error code and a message describing the error.

#####Scrypt Parameter Object
The scrypt parameter object is a JSON object that must have values for properties **N**, **r** and **p**. For example, it could look like this:

    {
      N: 1,
      r: 1,
      p: 1
    }

###Params
`params(maxtime, maxmem, maxmemfrac, callback_function)`

 * `maxtime` - [REQUIRED] - a decimal (double) representing the maxtime in seconds for running scrypt. 
 * `maxmem` - [OPTIONAL] - an integer, specifying the maximum number of bytes
 * `maxmemfrac` - [OPTIONAL] - a double value between 0.0 and 1.0, representing a normalized percentage value
 * `callback_function` - [OPTIONAL] - if present, will make this function asynchronous

####Params Config Object
The params config object is accessible from `scrypt.params.config`. It has the following default value:

    {
     maxmem: 0,
     maxmemfrac: 0.5
    }

  * `maxmem` - an integer representing the default value maxmem is set to if not explicitly defined in the function call
  * `maxmemfrac` - a double representing the default value maxmemfrac is set to if not explicitly defined in the function call

Read the section on [how memory is calculated](#how-memory-is-calculated) to get a better understanding of these values.

The return value will be a [scrypt parameter object](#scrypt-parameter-object)

###Hash
`hash(key, scrypt_parameters, callback_function)`

 * `key` - [REQUIRED] - an [encoded string or buffer](#encodings) representing the key to be hashed
 * `scrypt_parameters` - [REQUIRED] - a JSON object representing the [scrypt's internal parameters](#params)
 * `callback_function` - [OPTIONAL] - if present, will make this function asynchronous

####Hash Config Object
The hash config object is accessible from `scrypt.hash.config`. It has the following default value:

    {
     keyEncoding: 'buffer', 
     outputEncoding: 'buffer'
    }

 * `keyEncoding` - a string representing the [encoding](#encodings) of the input key
 * `outputEncoding` - a string representing the [encoding](#encodings) of the output returned to the user

The return value will be an [encoded string or buffer](#encodings) of the [hash format](#hash-format).

###Verify
`verify(hash, key, callback_function)`

 * `hash` - [REQUIRED] - an [encoded string or buffer](#encodings) of the output of the hash function
 * `key` - [REQUIRED] - an [encoded string or buffer](#encodings) representing the key to be hashed
 * `callback_function` - [OPTIONAL] - if present, will make this function asynchronous

####Verify Config Object
The verify config object is accessible from `scrypt.verify.config`. It has the following default value:

    {
     hashEncoding: 'buffer', 
     keyEncoding: 'buffer'
    }

 * `hashEncoding` - a string representing the [encoding](#encodings) of the input hash
 * `keyEncoding` - a string representing the [encoding](#encodings) of the input key

The return value will be a `boolean` representing if the hash can be derived from the key

###KDF
`kdf(key, scrypt_parameters, outputLength, salt, callback_function)`

 * `key` - [REQUIRED] - an [encoded string or buffer](#encodings) representing the key to be hashed
 * `scrypt_parameters` - [REQUIRED] - a JSON object representing the [scrypt's internal parameters](#params)
 * `outputLength` - [OPTIONAL] - an integer, representing the size in bytes of the output
 * `salt` - [OPTIONAL] - an [encoded string or buffer](#encodings) representing the value used for salt. If not defined, a random salt will be created.
 * `callback_function` - [OPTIONAL] - if present, will make this function asynchronous

The return value will be a JSON object with the following properties:

 1. **hash** - the resulting scrypt KDF hash
 2. **salt** - the salt used to make the hash

####KDF Config Object
The kdf config object is accessible from `scrypt.kdf.config`. It has the following default value:

    { 
     saltEncoding: 'buffer',
     keyEncoding: 'buffer',
     outputEncoding: 'buffer',
     defaultSaltSize: 32,
     outputLength: 64 
    }
 
 * `saltEncoding` - a string representing the [encoding](#encodings) of the input salt
 * `keyEncoding` - a string representing the [encoding](#encodings) of the input key
 * `outputEncoding` - a string representing the [encoding](#encodings) of the output returned to the user
 * `defaultSaltSize` - an integer representing the number of bytes used to create a random salt should it be necessary
 * `outputLength` - an integer representing the size of the output in bytes


###Backward Compatibility
####PasswordHash
`passwordHash(key, maxtime, maxmem, maxmemfrac, callback_function)`

 * `key` - [REQUIRED] - a key string.
 * `maxtime` - [REQUIRED] - a decimal (double) representing the maxtime in seconds for running scrypt. Use 0.1 (100 milliseconds) for interactive login.
 * `maxmem` - [OPTIONAL] - instructs scrypt to use the specified number of bytes of RAM (default 0).
 * `maxmemfrac` - [OPTIONAL] - instructs scrypt to use the specified fraction of RAM (defaults 0.5).
 * `callback_function` - [Optional] - a callback function that will handle processing when result is ready. If this argument is not present, the function will behave in a synchronous manner like the function below.

####PasswordHashSync
`passwordHashSync(key, maxtime, maxmem, maxmemfrac)`

 * `key` - [REQUIRED] - a password string.
 * `maxtime` - [REQUIRED] - a decimal (double) representing the maxtime in seconds for running scrypt. Use 0.1 (100 milliseconds) for interactive logins.
 * `maxmem` - [OPTIONAL] - instructs scrypt to use the specified number of bytes of RAM (default 0).
 * `maxmemfrac` - [OPTIONAL] - instructs scrypt to use the specified fracion of RAM (defaults 0.5).

####verifyHash
`verifyHash(hash, key, callback_function)` 

 * `hash` - [REQUIRED] - the password created with the above `passwordHash` function.
 * `key` - [REQUIRED] - a password string.
 * `callback_function` - [OPTIONAL] - a callback function that will handle processing when result is ready. If this argument is not present, the function will behave in a synchronous manner like the function below

####verifyHashSync
`verifyHashSync(hash, password)`

 * `hash` - [REQUIRED] - the password created with the above `passwordHash` function.
 * `password` - [REQUIRED] - a password string.

#Example Usage
##params

    var scrypt = require("scrypt");
	console.log(scrypt.params.config); //Outputs the config object to screen

	//Synchronous
	try {
		//Uses 0.1 for maxtime, and the values in the config object for maxmem and maxmemfrac
		var scryptParameters = scrypt.params(0.1); 
		console.log(scryptParameters);
	} catch(err) {
		
	}

	//Asynchronous
	scrypt.params(0.1, function(err, scryptParameters) {
		console.log(scryptParameters);
	});

##hash
	
	var scrypt = require("scrypt");
	var scryptParameters = scrypt.params(0.1);
	var key = new Buffer("this is a key"); //key defaults to buffer in config, so input must be a buffer

	//Synchronous example that will output in hexidecimal encoding
	scrypt.hash.config.outputEncoding = "hex";
	var hash = scrypt.hash(key, scryptParameters); //should be wrapped in try catch, but leaving it out for brevity
	console.log("Synchronous result: "+hash);

	//Asynchronous example that expects key to be ascii encoded
	scrypt.hash.config.keyEncoding = "ascii";
	scrypt.hash("ascii encoded key", {N: 1, r:1, p:1}, function(err, result){
		//result will be hex encoded
		//Note how scrypt parameters was passed as a JSON object
		console.log("Asynchronous result: "+hash);
	});

##verify

	var scrypt = require("scrypt");
	var scryptParameters = scrypt.params(0.1);
	scrypt.hash.config.keyEncoding = "ascii";
	scrypt.verify.config.keyEncoding = "ascii";
	var hash = scrypt.hash("password", scryptParameters);

	//Synchronous
	scrypt.verify(hash, "password"); //result will be true
	scrypt.verify(hash, "incorrect password"); //result will be false

	//Asynchronous
	scrypt.verify(hash, "password", function(err, result) {
		//result will be true
	});

##kdf
The [scrypt paper](http://www.tarsnap.com/scrypt/scrypt.pdf) lists four [test vectors](http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00#page-11) to test implementation. This example will show how to produce these test vectors from within this module.

####Test Vector 1

	var scrypt = require("scrypt");
    scrypt.kdf.config.saltEncoding = "ascii";
    var key = new Buffer("");

	//Synchronous
    var res = scrypt.kdf(key,{"N":16,"r":1,"p":1},64,"");
	console.log(res.hash.toString("hex"));

	//Asynchronous
    scrypt.kdf(key, {"N":16,"r":1,"p":1},64,"", function(err, res) {
		console.log(res.hash.toString("hex"));
    });

####Test Vector 2

	var scrypt = require("scrypt");
    scrypt.kdf.config.keyEncoding = "ascii";
    var salt = new Buffer("NaCl");

	//Synchronous
    var res = scrypt.kdf("password",{"N":1024,"r":8,"p":16},64,salt);
	console.log(res.hash.toString("hex"));

    scrypt.kdf("password", {"N":1024,"r":8,"p":16},64,salt, function(err, res) {
		console.log(res.hash.toString("hex"));
    });


####Test Vector 3
	
	var scrypt = require("scrypt");
    scrypt.kdf.config.outputEncoding = "hex";
    var key = new Buffer("pleaseletmein");
    var salt = new Buffer("SodiumChloride");

	//Synchronous
    var res = scrypt.kdf(key,{"N":16384,"r":8,"p":1},64,salt);
	console.log(res.hash);

	//Asynchronous
    scrypt.kdf(key, {"N":16384,"r":8,"p":1},64,salt, function(err, res) {
		console.log(res.hash);
    });


####Test Vector 4
Note: This test vector is very taxing in terms of resources.
	
	var scrypt = require("scrypt");
	scrypt.kdf.config.saltEncoding = "ascii";
	scrypt.kdf.config.keyEncoding = "ascii";

	//Synchronous
    var res = scrypt.kdf("pleaseletmein",{"N":1048576,"r":8,"p":1},64,"SodiumChloride");
	console.log(res.hash.toString("hex"));

	//Asynchronous
    scrypt.kdf("pleaseletmein", {"N":1048576,"r":8,"p":1},64,"SodiumChloride", function(err, res) {
		console.log(res.hash.toString("hex"));
    });

##Backward Compatibility Functions
These examples illustrate how to use the backward compatibility functions.
###Asynchronous Authentication And Verification
For interactive authentication, set `maxtime` to `0.1` - 100 milliseconds (although you should ensure that 100 milliseconds on your hardware is sufficiently secure).

####To create a password hash
 
    var scrypt = require("scrypt");
    var password = "This is a password";
    var maxtime = 0.1;

    scrypt.passwordHash(password, maxtime, function(err, pwdhash) {
        if (!err) {
            //pwdhash should now be stored in the database
        }
    });

Note: `maxmem` and `maxmemfrac` can also be passed to hash function. If they are not passed, then `maxmem` defaults to `0` and `maxmemfrac` defaults to `0.5`. If these values are to be passed, then they must be passed after `maxtime`  and before the callback function like so:
    var scrypt = require("scrypt");
    var password = "This is a password";
    var maxtime = 0.1;
    var maxmem = 0, maxmemfrac = 0.5;

    scrypt.passwordHash(password, maxtime, maxmem, maxmemfrac, function(err, pwdhash) {
        if (!err) {
            //pwdhash should now be stored in the database
        }
    });

####To verify a password hash

    var scrypt = require("scrypt");
    var password = "This is a password";
    var hash; //This should be obtained from the database

    scrypt.verifyHash(hash, password, function(err, result) {
        if (!err)
            return result; //Will be True
        
        return False;    
    });

###Synchronous Authentication And Verification
Again, for interactive authentication, set `maxtime` to `0.1` - 100 milliseconds. 

####To create a password hash
 
    var scrypt = require("scrypt");
    var password = "This is a password";
    var maxtime = 0.1;

    var hash = scrypt.passwordHashSync(password, maxtime);

Note: `maxmem` and `maxmemfrac` can also be passed to hash function. If they are not passed, then `maxmem` defaults to `0` and `maxmemfrac` defaults to `0.5`. If these values are to be passed, then they must be passed after `maxtime`  and before the callback function like so:

    var scrypt = require("scrypt");
    var password = "This is a password";
    var maxtime = 0.1;
    var maxmem = 0, maxmemfrac = 0.5;

    var hash = scrypt.passwordHashSync(password, maxtime, maxmem, maxmemfrac);

####To verify a password hash

    var scrypt = require("scrypt");
    var password = "This is a password";
    var hash; //This should be obtained from the database

    var result = scrypt.verifyHashSync(hash, password);

Note: There is no error description for the synchronous version. Therefore, if an error occurs, it will just return its result as `false`.

## FAQ
### General
#### What Platforms Are Supported?
This module supports most posix platforms, as well as Microsoft Windows. It has been tested on the following platforms: **Linux**, **MAC OS**, **SmartOS** (so its ready for Joyent Cloud) and **Microsoft Windows**. It also works on FreeBSD, OpenBSD, SunOS etc.

### Scrypt
####Why Use Scrypt?

It is probably the most advanced key derivation function available. This is is quote taken from a comment in hacker news:

>Passwords hashed with scrypt with sufficiently-high strength values (there are 3 tweakable input numbers) are fundamentally impervious to being cracked. I use the word "fundamental" in the literal sense, here; even if you had the resources of a large country, you would not be able to design any hardware (whether it be GPU hardware, custom-designed hardware, or otherwise) which could crack these hashes. Ever. (For sufficiently-small definitions of "ever". At the very least "within your lifetime"; probably far longer.)

#### What Are The Pros And Cons For Using Scrypt
#####Pros

* The scrypt algorithm has been published by [IETF](http://en.wikipedia.org/wiki/IETF) as an [Internet Draft](http://en.wikipedia.org/wiki/Internet_Draft) and is thus on track to becoming a standard. See [here](https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00) for the draft.
* It is being actively used in production at [Tarsnap](http://www.tarsnap.com/).
* It is much more secure than bcrypt.
* It is designed to be future proof against attacks with future (and more advanced) hardware.
* It is designed to defend against large scale custom hardware attacks.
* It is production ready.
* There is a scrypt library for most major scripting languages (Python, Ruby etc). Now this module provides the library for NodeJS :)

I will end this section with a quote from Colin Percival (author of scrypt):

> We estimate that on modern (2009) hardware, if 5 seconds are spent computing a derived key, the cost of a hardware brute-force attack against scrypt is roughly 4000 times greater than the cost of a similar attack against bcrypt (to find the same password), and 20000 times greater than a similar attack against PBKDF2.

#####Cons
There is just one con I can think of: It is a relatively new library (only been around since 2009). Cryptographers don't really like new libraries for production deployment as it has not been *battle tested*. That being said, it is being actively used in [Tarsnap](http://www.tarsnap.com/) (as mentioned above) and the author is very active.

### Hash
#### What Are The Essential Properties For Storing Passwords
Storing passwords requires three essential properties

* The password must not be stored in plaintext. (Therefore it is hashed).
* The password hash must be salted. (Making a rainbow table attack very difficult to pull off).
* The salted hash function must not be fast. (If someone does get hold of the salted hashes, their only option will be brute force which will be very slow).

As an example of how storing passwords can be done badly, take [LinkedIn](http://www.linkedin.com). In 2012, they [came under fire](http://thenextweb.com/socialmedia/2012/06/06/bad-day-for-linkedin-6-5-million-hashed-passwords-reportedly-leaked-change-yours-now/#!rS1HT) for using unsalted hashes to store their passwords. As most commentators at the time were focusing no salt being present, the big picture was missed. In fact, their biggest problem was that they used [sha1](http://en.wikipedia.org/wiki/SHA-1), a very fast hash function.

This module's [hash function](#hash-1) provides all the above properties

#### If random salts are used for each hash, why does each hash start with *c2NyeXB0* when using passwordHash
All hashes start with the word *"scrypt"*. The reason for this is because I am sticking to Colin Percival's (the creator of scrypt) hash reference implementation whereby he starts off each hash this way. The base64 encoding of the ascii *"scrypt"* is *c2NyeXB0*. Seeing as *passwordHash* defaults it's output to base64, every hash produced will start with *c2NyeXB0*. Next is the scrypt parameter. Users of scrypt normally do not change this information once it is settled upon (hence this will also look the same for each hash). 

To illustrate with an example, I have hashed two password: *password1* and *password2*. Their outputs are as follows:

    password1
    c2NyeXB0AAwAAAAIAAAAAcQ0zwp7QNLklxCn14vB75AYWDIrrT9I/7F9+lVGBfKN/1TH2hs
    /HboSy1ptzN0YzHJhC7PZIEPQzf2nuoaqVZg8VkKEJlo8/QaH7qjU2VwB
    
    password2
    c2NyeXB0AAwAAAAIAAAAAZ/+bp8gWcTZgEC7YQZeLLyxFeKRRdDkwbaGeFC0NkdUr/YFAWY
    /UwdOH4i/PxW48fXeXBDOTvGWtS3lLUgzNM0PlJbXhMOGd2bke0PvTSnW

As one can see from the above example, both hashes start off by looking similar (they both start with *c2NyeXB0AAwAAAAIAAAAA* - as explained above), but after this, things change very rapidly. In fact, I hashed the password *password1* again:

    password1
    c2NyeXB0AAwAAAAIAAAAATpP+fdQAryDiRmCmcoOrZa2mZ049KdbA/ofTTrATQQ+m
    0L/gR811d0WQyip6p2skXVEMz2+8U+xGryFu2p0yzfCxYLUrAaIzaZELkN2M6k0

Compare this hash to the one above. Even though they start off looking similar, their outputs are vastly different (even though it is the same password being hashed). This is because of the **random** salt that has been added, ensuring that no two hashes will ever be identical, even if the password that is being hashed is the same.

For those that are curious or paranoid, please look at how the hash is both [produced](https://github.com/barrysteyn/node-scrypt/blob/master/src/scryptwrapper/hash.c#L37-81) and [verified](https://github.com/barrysteyn/node-scrypt/blob/master/src/scryptwrapper/hash.c#L83-122) (you are going to need some knowledge of the [C language](http://c.learncodethehardway.org/book/) for this). 

##Credits
The scrypt library is Colin Percival's [scrypt](http://www.tarsnap.com/scrypt.html) project. This includes the encryption/decryption functions which are basically just wrappers into this library.

The password hash and verify functions are also very heavily influenced by the scrypt source code, with most functionality being copied from various placed within scrypt.

Syed Beparey was instrumental in getting the Windows build working, with most of the Windows build based off the work done by Dinesh Shanbhag.
