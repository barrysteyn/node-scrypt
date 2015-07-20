# Scrypt For Node/IO

Hi guys

Please test this for me. Here is a quick API:

 * scrypt.kdfSync
 * scrypt.kdf(key, paramsObject, function(err, obj){})
 * scrypt.paramsSync
 * scrypt.params(maxtime, maxmem, max_memfrac, function(err, obj) {})
 * scrypt.verifySync
 * scrypt.verify(KDF, key, function(err, obj) {})
 * scrypt.hashSync
 * scrypt.hash(key, paramsObject, outputLength, salt, function(err, obj) {})

key can be either a string or a buffer. All objects returned are buffer. Please provide feedback
