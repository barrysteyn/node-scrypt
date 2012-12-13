#Scrypt For NodeJS
node-scrypt is a native node C++ wrapper for Colin Percival's scrypt encryption utility. It is designed to be fully asynchronous (in fact, there is no synchronous mode) due to the time input of scrypt.

##What Is It?
Scrypt is an advanced crypto library that is mainly used for user authentication. More information can be found:

* [Tarsnap blurb about scrypt](http://www.tarsnap.com/scrypt.html) - Colin Percival (the author of scrypt) explains a bit about it.
* [Academic paper explaining scrypt](http://www.tarsnap.com/scrypt/scrypt.pdf).
* [Wikipedia Article on scrypt](http://en.wikipedia.org/wiki/Scrypt).

For additional interest, also read the [key derivation function](http://en.wikipedia.org/wiki/Key_derivation_function) article on wikipedia.

##Why Use It?
When used for authentication, it is probably the most advanced library out there. This is quote taken from a comment in hacker news:

>Passwords hashed with scrypt with sufficiently-high strength values (there are 3 tweakable input numbers) are fundamentally impervious to being cracked. I use the word "fundamental" in the literal sense, here; even if you had the resources of a large country, you would not be able to design any hardware (whether it be GPU hardware, custom-designed hardware, or otherwise) which could crack these hashes. Ever. (For sufficiently-small definitions of "ever". At the very least "within your lifetime"; probably far longer.)

The *three tweakable* inputs mentioned above are as follows (Quoting from the author):

###maxtime
>maxtime will instruct scrypt to spend at most maxtime seconds computing the derived encryption key from the password; for encryption, this value will determine how secure the encrypted data is, while for decryption this value is used as an upper limit (if scrypt detects that it would take too long to decrypt the data, it will exit with an error message).

###maxmemfrac
>maxmemfrac instructs scrypt to use at most the specified fraction of the available RAM for computing the derived encryption key. For encryption, increasing this value might increase the security of the encrypted data, depending on the maxtime value; for decryption, this value is used as an upper limit and may cause scrypt to exit with an error.

###maxmem
>maxmem instructs scrypt to use at most the specified number of bytes of RAM when computing the derived encryption key. 

Here are some pros and cons for using it:

###Pros

* It is being actively used in production at [Tarsnap](http://www.tarsnap.com/).
* It is much more secure than bcrypt.
* It is designed to be future proof against attacks with future (and more advanced) hardware.
* It is designed to defend against large scale custom hardware attacks.
* It is production ready.
* There is a scrypt library for most major scripting languages (Python, Ruby etc). Now this module provides the library for NodeJS :)

I will end this section with a quote from Colin Percival (author of scrypt):

> We estimate that on modern (2009) hardware, if 5 seconds are spent computing a derived key, the cost of a hardware brute-force attack against scrypt is roughly 4000 times greater than the cost of a similar attack against bcrypt (to find the same password), and 20000 times greater than a similar attack against PBKDF2.

###Cons
There is just one con: It is a relatively new library (only been around since 2009). Cryptographers don't really like new libraries for production deployment as it has not been *battle tested*. That being said, it is being actively used in [Tarsnap](http://www.tarsnap.com/) (as mentioned above) and the author is very active.

#Security Issues/Concerns
As should be the case with any security tool, this library should be scrutinized by anyone using it. If you find or suspect an issue with the code- please bring it to my attention and I'll spend some time trying to make sure that this tool is as secure as possible.

#Dependencies

#Installation Instructions
As of now (Dec 2012), this library has been tested and works on Linux (Ubuntu to be exact).
##From NPM
This will be ready within the next 24 hours.
##From Source
You will need `node-gyp` to get this to work (install it if you don't have it: `npm install -g node-gyp`):

    git clone https://github.com/barrysteyn/node-scrypt.git
    cd node-scrypt
    node-gyp configure build

The module can be found in the `build/Release` folder with the name `scrypt_crypto.node`.

#Usage
I will write an example application that uses scrypt for authentication in a few days time. What follows here is using scrypt to encrypt and decrypt data. Note that for the case of pure encryption and decryption, scrypt is not a good candidate (rather use [AES]()). Remember that scrypt is designed to be a key derivation function, and therefore being *slow* is an advantage.

    var scrypt = require("./build/Release/scrypt_crypto");
    var message = "Hello World";
    var password = "Pass";
    var max_time = 1.0;

    scrypt.encrypt(message, password, max_time, function(err, cipher) {
        console.log(cipher);
        scrypt.decrypt(cipher, password, max_time, function(err, msg) {
            console.log(msg);
        });
    });

Note that `maxmem` and `maxmemfrac` can also be passed to the functions. If they are not passed, then `maxmem` defaults to `0` and `maxmemfrac` defaults to `0.5`. If these values are to be passed, then they must be passed after `max_time`  and before the callback function like so:
    
    var scrypt = require("./build/Release/scrypt_crypto");
    var message = "Hello World";
    var password = "Pass";
    var max_time = 1.0;
    var maxmem = 1; //Defaults to 0 if not set
    var maxmemfrac = 1.5; //Defaults to 0.5 if not set

    scrypt.encrypt(message, password, max_time, maxmem, maxmemfrac, function(err, cipher) {
        console.log(cipher);
        scrypt.decrypt(cipher, password, max_time, maxmem, maxmemfrac, function(err, msg) {
            console.log(msg);
        });
    });

#Still To Do

1. Finish writing testing scripts.
2. Find collaborators to help port it to windows.
3. Make an example password authentication script.
