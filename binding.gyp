{
  'variables': {
    'openssl_include%':'<(node_root_dir)/deps/openssl/openssl/include',
    'compiler-flags': [],
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
        'conditions': [
          ['target_arch=="ia32"',{
            'compiler-flags': [
              '-msse2',
            ],
          }],
        ],
        'scrypt_platform_specific_files': [
          'scrypt/scrypt-1.1.6/lib/util/memlimit.c',
          'scrypt/scrypt-1.1.6/lib/scryptenc/scryptenc.c',
          'scrypt/scrypt-1.1.6/lib/crypto/crypto_aesctr.c',
        ],
        'platform_specific_include_dirs': [
          'scrypt/scrypt-1.1.6/lib/scryptenc',
        ],
      }],

      # SSE support
      ['target_arch=="x64" or target_arch=="ia32"', {
        'scrypt_arch_specific_files': [
          'scrypt/scrypt-1.1.6/lib/crypto/crypto_scrypt-sse.c',
        ],
      },{
        'scrypt_arch_specific_files': [
          'scrypt/scrypt-1.1.6/lib/crypto/crypto_scrypt-nosse.c',
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
    'target_name': 'copied_files',
    'conditions': [
      ['OS=="win"', {
        'copies' : [{
          'destination':'scrypt/scrypt-1.1.6/',
          'files' : [
            'scrypt/win/include/config.h'
          ]
        }],
      }],
      ['OS!="win"', {
        'copies' : [{
          'destination':'scrypt/scrypt-1.1.6/',
          'files' : [
            'scrypt/configuration/config_output/config.h'
          ]
        }],
      }],
    ],
  },

  {
    'target_name': 'scrypt_lib',
    'type' : 'static_library',
    'sources': [
      'scrypt/scrypt-1.1.6/lib/crypto/sha256.c',
      '<@(scrypt_arch_specific_files)',
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
    'cflags': ['<@(compiler-flags)'],
    'defines': [
      'HAVE_CONFIG_H'
    ],
    'dependencies': ['copied_files'],
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
      'src/scryptwrapper/inc',
      'scrypt/scrypt-1.1.6/lib/util',
      'scrypt/scrypt-1.1.6/lib/crypto',
      'scrypt/scrypt-1.1.6/lib/scryptenc',
      'scrypt/scrypt-1.1.6',
      'src/util',
      '<(openssl_include)',
    ],
    'cflags': ['<@(compiler-flags)'],
    'conditions': [['OS=="win"', {'include_dirs': ['scrypt/win/include']}]],
    'defines': [
      'HAVE_CONFIG_H'
    ],
    'dependencies': ['scrypt_lib'],
  },

  {
    'target_name': 'scrypt',
    'sources': [
      'src/node-boilerplate/scrypt_common.cc',
      'src/node-boilerplate/scrypt_params_async.cc',
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
    'conditions': [
      ['OS=="win"', {'libraries': ['-l<(openssl_lib)']}],
      ['OS!="win"', {'libraries': ['<@(config_libs)'],}],
    ],
    'dependencies': ['scrypt_wrapper'],
  }],
}
