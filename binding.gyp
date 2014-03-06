{
  'variables': {
    'openssl_include%':'<(node_root_dir)/deps/openssl/openssl/include',
    'conditions' : [
      ['OS=="win"',{
        'scrypt_platform_specific_files': [
          'scrypt/win/memlimit.c',
          'scrypt/win/mman.c',
          'scrypt/win/gettimeofday.c'
        ],
        'platform_specific_include_dirs': [
          'scrypt/win/include',
        ],
        'conditions': [
          ['target_arch=="x64"', {
            'openssl_lib%': '<(PRODUCT_DIR)../../scrypt/win/libs/openssl_64/libeay32.lib',
          }],
          ['target_arch=="ia32"', {
            'openssl_lib%': '<(PRODUCT_DIR)../../scrypt/win/libs/openssl_32/libeay32.lib',
          }],
        ],
      }],
      ['OS!="win"', {
        'config_libs': '<!(scrypt/configuration/posixconfig)',
        'scrypt_platform_specific_files': [
          'scrypt/scrypt-1.1.6/lib/util/memlimit.c',
          'scrypt/scrypt-1.1.6/lib/scryptenc/scryptenc.c',
          'scrypt/scrypt-1.1.6/lib/crypto/crypto_aesctr.c',
        ],
        'platform_specific_include_dirs': [
          'scrypt/scrypt-1.1.6/lib/scryptenc',
        ],
      }],
    ],
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

  'targets' : [{
    'target_name': 'scrypt_lib',
    'type' : 'static_library',
    'sources': [
      'scrypt/scrypt-1.1.6/lib/crypto/sha256.c',
      'scrypt/scrypt-1.1.6/lib/crypto/crypto_scrypt-sse.c',
      'scrypt/scrypt-1.1.6/lib/scryptenc/scryptenc_cpuperf.c',
      '<@(scrypt_platform_specific_files)',
    ],
    'include_dirs': [
      'scrypt/scrypt-1.1.6',
      'scrypt/scrypt-1.1.6/lib/util',
      'scrypt/scrypt-1.1.6/lib/crypto',
      '<@(platform_specific_include_dirs)',
      '<(openssl_include)'
    ],
    'defines': [
      'HAVE_CONFIG_H'
    ],
  },

  {
    'target_name': 'scrypt_wrapper',
    'type' : 'static_library',
    'sources': [
      'src/util/salt.c',
      'src/scryptwrapper/keyderivation.c',
      'src/scryptwrapper/pickparams.c',
      'src/scryptwrapper/hash.c'
    ],
    'include_dirs': [
      'scrypt/scrypt-1.1.6/lib/util',
      'scrypt/scrypt-1.1.6/lib/crypto',
      'scrypt/scrypt-1.1.6/lib/scryptenc',
      'scrypt/scrypt-1.1.6',
      'src/util',
      '<(openssl_include)',
    ],
    'conditions': [['OS=="win"', {'include_dirs': ['scrypt/win/include']}]],
    'defines': [
      'HAVE_CONFIG_H'
    ],
    'dependencies': ['scrypt_lib'],
  },

  {
    'target_name': 'scrypt',
    'sources': [
      'scrypt_node.cc',
      'src/node-boilerplate/common.cc',
      'src/node-boilerplate/scrypt_error.cc',
      'src/node-boilerplate/scrypt_config_object.cc',
      'src/node-boilerplate/scrypt_params.cc',
      'src/node-boilerplate/scrypt_kdf.cc',
      'src/node-boilerplate/scrypt_hash.cc',
      'src/node-boilerplate/scrypt_verify.cc',
    ],
    'include_dirs': [
      'src/util',
      'src/scryptwrapper',
    ],
    'conditions': [
      ['OS=="win"', {'libraries': ['-l<(openssl_lib)']}],
      ['OS!="win"', {'libraries': ['<@(config_libs)']}]
    ],
    'dependencies': ['scrypt_wrapper'],
  }],
}
