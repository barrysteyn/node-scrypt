#Scrypt For NodeJS
node-scrypt is a native node C++ wrapper for Colin Percival's scrypt [key derivation](http://en.wikipedia.org/wiki/Key_derivation_function) utility.

##What Is Scrypt? 
Scrypt is an advanced crypto library used mainly for [key derivation](http://en.wikipedia.org/wiki/Key_derivation_function) (i.e. password authenticator). More information can be found here:

* [Tarsnap blurb about scrypt](http://www.tarsnap.com/scrypt.html) - Colin Percival (the author of scrypt) explains a bit about it.
* [Academic paper explaining scrypt](http://www.tarsnap.com/scrypt/scrypt.pdf).
* [Wikipedia Article on scrypt](http://en.wikipedia.org/wiki/Scrypt).

For additional interest, read the article on wikipedias about the [key derivation function](http://en.wikipedia.org/wiki/Key_derivation_function).

###The Three Essential Properties Of Password Key Derivation
Password key derivation requires three properties:

* The password must not be stored in plaintext (so it is hashed).
* The password hash must be salted (making a rainbow table attack very difficult to pull off).
* The salted hash function must not be fast (so if someone does get hold of the salted hashes, their only option will be a *slow* brute force attack).

### What This Module Provides

Scrypt key derivation and Scrypt encryption that can be called both *asynchronously* and *synchronously*.

####Scrypt password key derivation
This scrypt library (and this module) handles all the above essential properties. The last item seems strange: Computer scientists are normally pre-occupied with making things fast. Yet it is this property that sets Scrypt apart from the competition. As computers evolve and get more powerful, they are able to attack this property more efficiently. This has become especially apparent with the rise of parallel programming. Scrypt aims to defend against all types of attacks, not matter the attackers power now or in the future.

####Scrypt encryption
I suspect scrypt will be used mainly as a password key derivation function (its author's intended use), but I have also ported the scrypt encryption and decryption functions as implementations for them were available from the author. Performing scrypt cryptography is done if you value security over speed. Scrypt is more secure than a vanilla block cipher (e.g. AES) but it is much slower. It is also the basis for the key derivation functions.

##Why Use Scrypt?
It is probably the most advanced key derivation function available. This is is quote taken from a comment in hacker news:

>Passwords hashed with scrypt with sufficiently-high strength values (there are 3 tweakable input numbers) are fundamentally impervious to being cracked. I use the word "fundamental" in the literal sense, here; even if you had the resources of a large country, you would not be able to design any hardware (whether it be GPU hardware, custom-designed hardware, or otherwise) which could crack these hashes. Ever. (For sufficiently-small definitions of "ever". At the very least "within your lifetime"; probably far longer.)

See the *The Three Tweakable Inputs* section below for information about that.

### Pros And Cons
   
####Pros
* The scrypt algorithm has been published by [IETF](http://en.wikipedia.org/wiki/IETF) as an [Internet Draft](http://en.wikipedia.org/wiki/Internet_Draft) and is thus on track to becoming a standard. See [here](https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00) for the draft.
* It is being actively used in production at [Tarsnap](http://www.tarsnap.com/).
* It is much more secure than bcrypt.
* It is designed to be future proof against attacks with future (and more advanced) hardware.
* It is designed to defend against large scale custom hardware attacks.
* It is production ready.
* There is a scrypt library for most major scripting languages (Python, Ruby etc). This module provides the library for NodeJS :)

I will end this section with a quote from Colin Percival (author of scrypt):

> We estimate that on modern (2009) hardware, if 5 seconds are spent computing a derived key, the cost of a hardware brute-force attack against scrypt is roughly 4000 times greater than the cost of a similar attack against bcrypt (to find the same password), and 20000 times greater than a similar attack against PBKDF2.

####Cons
There is just one con I can think of: It is a relatively new library (only been around since 2009). Cryptographers don't really like new libraries for production deployment as it has not been *battle tested*. That being said, it is being actively used in [Tarsnap](http://www.tarsnap.com/) (as mentioned above) and the author is very active.

## How it works - The Three Tweakable Inputs
<u>**Note**: This is a very important section to understand</u>. 

The *three tweakable* inputs mentioned above are as follows (Quoting from the author):

**maxtime**
>maxtime will instruct scrypt to spend at most maxtime seconds computing the derived encryption key from the password; [If using scrypt] for encryption, this value will determine how secure the encrypted data is, while for decryption this value is used as an upper limit (if scrypt detects that it would take too long to decrypt the data, it will exit with an error message).

**maxmemfrac**
>maxmemfrac instructs scrypt to use at most the specified fraction of the available RAM for computing the derived encryption key. For encryption, increasing this value might increase the security of the encrypted data, depending on the maxtime value; for decryption, this value is used as an upper limit and may cause scrypt to exit with an error.

**maxmem**
>maxmem instructs scrypt to use at most the specified number of bytes of RAM when computing the derived encryption key. 


**A Note On How Memory Is Calculated**: `maxmem` is often defaulted to `0`. This does not mean that `0` RAM is used. Instead, at the very least, 1MiB of ram will be used. To quote from Colin Percival:

> the system [will use] the amount of RAM which [is] specified [as the] fraction of the available RAM, but no more than maxmem, and no less than 1MiB

### Internal parameters

The three tweakable inputs mentioned above are actually just *human understandable* inputs into a translation function that produces the inputs required for the internal scrypt cryptographic function. These inputs (as defined in the [scrypt paper](http://www.tarsnap.com/scrypt/scrypt.pdf)) are as follows:

1. **N** - general work factor, iteration count.
2. **r** - blocksize in use for underlying hash; fine-tunes the relative memory-cost.
3. **p** - parallelization factor; fine-tunes the relative cpu-cost.

Values for *maxtime*, *maxmemfrac* and *maxmem* are translated into *N*, *r*, and *p*, which are then fed to the scrypt function. The translation function also takes into account the CPU and Memory capabilities of a machine. Therefore values of *N*, *r* and *p* may differ for different machines that have different specs.

#Security Issues/Concerns
As should be the case with any security tool, this library should be scrutinized by anyone using it. If you find or suspect an issue with the code- please bring it to my attention and I'll spend some time trying to make sure that this tool is as secure as possible.

#Platforms
This library works on **Linux** and **MAC OS**. Windows support is coming very soon.

#Installation Instructions
This library has been tested and works on Linux (Ubuntu to be exact) and Mac OS (thanks to [Kelvin Wong](https://github.com/kelvinwong-ca)).
##From NPM

    npm install scrypt

##From Source
You will need `node-gyp` to get this to work (install it if you don't have it: `npm install -g node-gyp`):

    git clone https://github.com/barrysteyn/node-scrypt.git
    cd node-scrypt
    node-gyp configure build

#Testing
Testing is accomplished with the [node tap module](https://github.com/isaacs/node-tap).
##If installed via NPM
To test, go to the folder where scrypt was installed, and type:

    cd node_modules/scrypt
    npm install
    node tests/scrypt-tests

##If installed via source
Go to the folder where scrypt was installed and type:
    
    cd node-scrypt
    npm install
    node tests/scrypt-tests

#Api

All scrypt output is encoded into Base64 using [René Nyffenegger](http://www.adp-gmbh.ch/) [library](http://www.adp-gmbh.ch/cpp/common/base64.html). The character set used to encode all output is `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`.

There are both asynchronous and synchronous functions available. It is highly recommended not to use the synchronous version unless necessary due to the fact that Node's event loop will be blocked for the duration of these purposefully slow functions.

##Authentication

Note: This scrypt library outputs what we will call an *scrypt hash-token*, which has encoded in it both the raw password-hash and the salt needed for hash verification. 

`passwordHash(password, maxtime, maxmem, maxmemfrac, callback_function)`

`passwordHashSync(password, maxtime, maxmem, maxmemfrac)`

* `password` - a password string.
* `maxtime` - a decimal (double) representing the maxtime in seconds for running scrypt. Use 0.1 (100 milliseconds) for interactive logins.
* `maxmem` - (optional: default 0) - instructs scrypt to use the specified number of bytes of RAM (default 0).
* `maxmemfrac` - (optional: default 0.5) - instructs scrypt to use the specified fracion of RAM (defaults 0.5).
* `callback_function(err, scryptHashToken)` - a callback function that will handle processing when result is ready. Not relevant for `passwordHashSync`.
  * `err` - an error message if there was an error, otherwise null.
  * `scryptHashToken` - the scrypt hash-token containing both the raw password hash and the salt needed to verify the hash.

`verifyHash(hash, password, callback_function)` 

`verifyHashSync(hash, password)`

* `scryptHashToken` - the *Scrypt hash-token* created with the above `passwordHash` function.
* `password` - the password string to verify.
* `callback_function(err, valid)` - a callback function that will handle processing when result is ready. Not relevant for `verifyHashSync`.
  * `err` - an error message if there was an error, otherwise null.
  * `valid` - true if the password matches the *Scrypt hash-token*, false if not.
  
Note: There is no error description for the synchronous version. If an error occurs, it will just return `false`.
  
### Example Scrypt hash-token generation
 
    var scrypt = require("scrypt");

	// asynchronous
    scrypt.passwordHash("This is a password", 0.1, function(err, scryptHashToken) {
        if (!err) {
            //scryptHashToken should now be stored in a database
        }
    });
    
    // synchronous
    var scryptHashToken = scrypt.passwordHashSync("This is a password", 0.1);

	// asynchronous (passing maxmem and maxmemfrac)
    scrypt.passwordHash("This is a password", 0.1, 2000000, 0.6, function(err, scryptHashToken) {
        if (!err) {
            //scryptHashToken should now be stored in the database
        }
    });
    
    // synchronous (passing maxmem and maxmemfrac)
    var scryptHashToken = scrypt.passwordHashSync("This is a password", 0.1, 2000000, 0.6);

### Example Scrypt hash-token verification

    var scrypt = require("scrypt");
    var scryptHashToken; //This should be obtained from a database

    scrypt.verifyHash(scryptHashToken, "This is a password", function(err, result) {
        if (!err)
            return result; //Will be True
        
        return False;    
    });
  
##Encryption/Decryption

`encrypt(message, password, maxtime, maxmem, maxmemfrac, callback_function)`

`encryptSync(message, password, maxtime, maxmem, maxmemfrac)`

* `message` - the message data to be encrypted.
* `password` - a password string.
* `maxtime` - a decimal (double) representing the maxtime in seconds for running scrypt.
* `maxmem` - (optional: default 0) - instructs scrypt to use the specified number of bytes of RAM (default 0).
* `maxmemfrac` - (optional: default 0.5) - instructs scrypt to use the specified fracion of RAM (defaults 0.5).
* `callback_function(err, cipher)` - a callback function that will handle processing when result is ready. Not relevant for `encryptSync`.
  * `err` - an error message if there was an error, otherwise null.
  * `cipher` - the encrypted message.
  
`decrypt(cipher, password, maxtime, maxmem, maxmemfrac, callback_function)`

`decryptSync(cipher, password, maxtime, maxmem, maxmemfrac)`

* `cipher` - the cipher to be decrypted.
* `password` - a password string.
* `maxtime` - a decimal (double) representing the maxtime in seconds for running scrypt.
* `maxmem` - (optional) - instructs scrypt to use the specified number of bytes of RAM (default 0).
* `maxmemfrac` - (optional) - instructs scrypt to use the specified fracion of RAM (defaults 0.5).
* `callback_function(err, msg)` - a callback function that will handle processing when result is ready. Not relevant for `decryptSync`.
  * `err` - an error message if there was an error, otherwise null.
  * `msg` - the decrypted message.
  
### Example Encryption/Decryption

    var scrypt = require("scrypt");

	// asynchronous
    scrypt.encrypt("Hello World", "Pass", 1.0, function(err, cipher) {
        console.log(cipher);
        scrypt.decrypt(cipher, "Pass", 1.0, function(err, msg) {
            console.log(msg);
        });
    });
    
    // synchronous
    var cipher = scrypt.encryptSync("Hello World", "Pass", 1.0);
    var plainText = scrypt.decryptSync(cipher, "Pass", 1.0);

	// asynchronous (passing maxmem and maxmemfrac)
    scrypt.encrypt("Hello World", "Pass", 1.0, 1, 1.5, function(err, cipher) {
        console.log(cipher);
        scrypt.decrypt(cipher, "Pass", 1.0, 1, 1.5, function(err, msg) {
            console.log(msg);
        });
    });

    // synchronous (passing maxmem and maxmemfrac)
    var cipher = scrypt.encryptSync("Hello World", "Pass", 1.0, 1, 1.5);
    var plainText = scrypt.decryptSync(cipher, "Pass", 1.0, 1, 1.5);

#Credits
The scrypt library is Colin Percival's [scrypt](http://www.tarsnap.com/scrypt.html) project. This includes the encryption/decryption functions which are basically just wrappers into this library.

The password hash and verify functions are also very heavily influenced by the scrypt source code, with most functionality being copied from various placed within scrypt.

#Contributors

* [René Nyffenegger](http://www.adp-gmbh.ch/) - produced original Base64 encoding code.
* [Kelvin Wong](https://github.com/kelvinwong-ca) - MAC OS compilation and testing.
