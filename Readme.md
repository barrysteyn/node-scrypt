# Scrypt For Node/IO

Hi guys

Please test this for me. Here is a quick API:

 * Scrypt.KDFSync
 * Scrypt.KDF(key, paramsObject, function(err, obj){})
 * Scrypt.ParamsSync
 * Scrypt.Params(maxtime, maxmem, max_memfrac, function(err, obj) {})
 * Scrypt.VerifySync
 * Scrypt.Verify(KDF, key, function(err, obj) {})
 * Scrypt.HashSync
 * Scrypt.Hash(key, paramsObject, outputLength, salt, function(err, obj) {})

key can be either a string or a buffer. All objects returned are buffer. Please provide feedback
