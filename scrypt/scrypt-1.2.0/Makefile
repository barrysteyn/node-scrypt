node-scrypt: main.o hash.o keyderivation.o pickparams.o crypto_scrypt.o crypto_scrypt_smix.o warnp.o sha256.o insecure_memzero.o salt.o memlimit.o scryptenc_cpuperf.o
	gcc -o node-scrypt main.o hash.o keyderivation.o pickparams.o crypto_scrypt.o crypto_scrypt_smix.o warnp.o sha256.o insecure_memzero.o salt.o memlimit.o scryptenc_cpuperf.o -lcrypto

node-scrypt-pp: main.o pickparams.o memlimit.o scryptenc_cpuperf.o crypto_scrypt.o crypto_scrypt_smix.o warnp.o sha256.o insecure_memzero.o
	gcc -o node-scrypt main.o pickparams.o memlimit.o scryptenc_cpuperf.o crypto_scrypt.o crypto_scrypt_smix.o warnp.o sha256.o insecure_memzero.o

node-scrypt-kd: main.o keyderivation.o hash.o crypto_scrypt.o crypto_scrypt_smix.o warnp.o sha256.o insecure_memzero.o salt.o
	gcc -o node-scrypt main.o keyderivation.o hash.o crypto_scrypt.o crypto_scrypt_smix.o warnp.o sha256.o insecure_memzero.o salt.o -lcrypto

node-scrypt-hash: hash.o crypto_scrypt.o crypto_scrypt_smix.o warnp.o sha256.o insecure_memzero.o
	gcc -o node-scrypt-hash main.o hash.o crypto_scrypt.o crypto_scrypt_smix.o warnp.o sha256.o insecure_memzero.o

scrypt: main.o scryptenc.o insecure_memzero.o readpass.o warnp.o crypto_aes.o crypto_aesctr.o entropy.o crypto_entropy.o crypto_scrypt.o sha256.o crypto_scrypt_smix.o memlimit.o scryptenc_cpuperf.o hash.o pickparams.o keyderivation.o salt.o
	gcc -o scrypt main.o insecure_memzero.o scryptenc.o readpass.o warnp.o crypto_aes.o crypto_aesctr.o entropy.o crypto_entropy.o crypto_scrypt.o sha256.o crypto_scrypt_smix.o memlimit.o scryptenc_cpuperf.o -lcrypto

main.o: main.c
	gcc -c main.c -DHAVE_CONFIG_H -I ./libcperciva/util/ -I ./lib/scryptenc/

salt.o: salt.c
	gcc -c salt.c

hash.o: hash.c
	gcc -c hash.c -I ./lib/crypto/

pickparams.o: pickparams.c
	gcc -c pickparams.c -DHAVE_CONFIG_H -I ./lib/util/ -I ./lib/scryptenc/

keyderivation.o: keyderivation.c
	gcc -c keyderivation.c -I ./libcperciva/alg -I ./libcperciva/util/ -I ./

insecure_memzero.o: libcperciva/util/insecure_memzero.c
	gcc -c libcperciva/util/insecure_memzero.c

scryptenc.o: lib/scryptenc/scryptenc.c
	gcc -c lib/scryptenc/scryptenc.c -DHAVE_CONFIG_H -I ./lib/scryptenc/ -I ./ -I ./libcperciva/crypto/ -I ./libcperciva/util/ -I ./libcperciva/alg/ -I ./lib/crypto/ -I ./lib/util/

readpass.o: libcperciva/util/readpass.c
	gcc -c libcperciva/util/readpass.c

warnp.o: libcperciva/util/warnp.c
	gcc -c libcperciva/util/warnp.c

# Note - there is a different file that we should use if cpu supports what we need
crypto_aes.o: libcperciva/crypto/crypto_aes.c
	gcc -c libcperciva/crypto/crypto_aes.c -I ./libcperciva/cpusupport/ -I ./libcperciva/util/

crypto_aes_aesni.o: libcperciva/crypto/crypto_aes_aesni.c
	gcc -c libcperciva/crypto/crypto_aes_aesni.c -I ./libcperciva/cpusupport/ -I ./libcperciva/util/

crypto_aesctr.o: libcperciva/crypto/crypto_aesctr.c
	gcc -c libcperciva/crypto/crypto_aesctr.c -I ./libcperciva/util

crypto_entropy.o: libcperciva/crypto/crypto_entropy.c
	gcc -c libcperciva/crypto/crypto_entropy.c -I ./libcperciva/util/ -I ./libcperciva/alg/

entropy.o: libcperciva/util/entropy.c
	gcc -c libcperciva/util/entropy.c

crypto_scrypt.o: lib/crypto/crypto_scrypt.c
	gcc -c lib/crypto/crypto_scrypt.c -DHAVE_CONFIG_H -I ./ -I ./libcperciva/cpusupport/ -I ./libcperciva/alg/ -I ./libcperciva/util/

sha256.o: libcperciva/alg/sha256.c
	gcc -c libcperciva/alg/sha256.c -I ./libcperciva/util/

crypto_scrypt_smix.o: lib/crypto/crypto_scrypt_smix.c
	gcc -c lib/crypto/crypto_scrypt_smix.c -I ./libcperciva/alg/ -I ./libcperciva/util/

memlimit.o: lib/util/memlimit.c
	gcc -c lib/util/memlimit.c -DHAVE_CONFIG_H -I ./

scryptenc_cpuperf.o: lib/scryptenc/scryptenc_cpuperf.c
	gcc -c lib/scryptenc/scryptenc_cpuperf.c  -DHAVE_CONFIG_H -I ./ -I ./lib/crypto/

clean:
	rm *.o
