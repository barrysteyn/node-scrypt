{
  'variables': {
    'compiler-flags': [],
  },

  'target_defaults': {
    'default_configuration': 'Release',
    'msvs_settings': {
      'VCCLCompilerTool': {
        'RuntimeLibrary': 0, # static release
        'ExceptionHandling': '2',
        'AdditionalOptions': ['/EHsc'],
        'DisableSpecificWarnings': ['4506'],
      },
    },
  },

  'targets': [
    {
      'target_name': 'scrypt_lib',
      'type' : 'static_library',
      'sources': [
        'scrypt/scrypt-1.2.0/lib/crypto/crypto_scrypt.c',
        'scrypt/scrypt-1.2.0/lib/crypto/crypto_scrypt_smix.c',
        'scrypt/scrypt-1.2.0/libcperciva/util/warnp.c',
        'scrypt/scrypt-1.2.0/libcperciva/alg/sha256.c',
        'scrypt/scrypt-1.2.0/libcperciva/util/insecure_memzero.c',
        #'scrypt/scrypt-1.2.0/lib/util/memlimit.c',
        'scrypt/scrypt-1.2.0/lib/scryptenc/scryptenc_cpuperf.c',
      ],
      'include_dirs': [
        'scrypt/scrypt-1.2.0/',
        'scrypt/scrypt-1.2.0/libcperciva/cpusupport',
        'scrypt/scrypt-1.2.0/libcperciva/alg',
        'scrypt/scrypt-1.2.0/libcperciva/util',
        'scrypt/scrypt-1.2.0/lib/crypto',
      ],
      'cflags': ['<@(compiler-flags)'],
      'defines': [
        'HAVE_CONFIG_H'
      ],
    },
    {
      'target_name': 'scrypt_wrapper',
      'type' : 'static_library',
      'sources': [
        'src/util/memlimit.c',
        'src/scryptwrapper/keyderivation.c',
        'src/scryptwrapper/pickparams.c',
        'src/scryptwrapper/hash.c'
      ],
      'include_dirs': [
        'src/scryptwrapper/inc',
        'src',
        'scrypt/scrypt-1.2.0/libcperciva/alg',
        'scrypt/scrypt-1.2.0/libcperciva/util',
        'scrypt/scrypt-1.2.0/lib/crypto',
        'scrypt/scrypt-1.2.0/lib/util/',
        'scrypt/scrypt-1.2.0/lib/scryptenc/',
      ],
      'cflags': ['<@(compiler-flags)'],
      'defines': [
        'HAVE_CONFIG_H'
      ],
    },
    {
      'target_name': 'scrypt',
      'sources': [
        'src/node-boilerplate/scrypt_common.cc',
        #'src/node-boilerplate/scrypt_params_async.cc',
        'src/node-boilerplate/scrypt_params_sync.cc',
        'src/node-boilerplate/scrypt_kdf_async.cc',
        'src/node-boilerplate/scrypt_kdf_sync.cc',
        'src/node-boilerplate/scrypt_kdf-verify_sync.cc',
        'src/node-boilerplate/scrypt_kdf-verify_async.cc',
        'src/node-boilerplate/scrypt_hash_sync.cc',
        'src/node-boilerplate/scrypt_hash_async.cc',
        'scrypt_node.cc'
      ],
      'include_dirs': [
        '<!(node -e "require(\'nan\')")',
        'src/util',
        'src/scryptwrapper/inc',
        'src/node-boilerplate/inc'
      ],
      'cflags': ['<@(compiler-flags)'],
      'dependencies': ['scrypt_wrapper','scrypt_lib'],
    }
  ],
}
