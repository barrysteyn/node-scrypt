{
    'targets' : [
        {
            'target_name': 'scrypt_lib',
            'type': 'static_library',
            'defines': [
                'HAVE_CONFIG_H'                
            ],
            'include_dirs' : [
                'scrypt-1.1.6',
                'scrypt-1.1.6/lib/util',
                'scrypt-1.1.6/lib/crypto',
                'scrypt-1.1.6/lib/scryptenc'
            ],
            'sources': [
                'scrypt-1.1.6/lib/scryptenc/scryptenc.c',
                'scrypt-1.1.6/lib/util/memlimit.c',
                'scrypt-1.1.6/lib/scryptenc/scryptenc_cpuperf.c',
                'scrypt-1.1.6/lib/crypto/sha256.c',
                'scrypt-1.1.6/lib/crypto/crypto_aesctr.c',
                'scrypt-1.1.6/lib/crypto/crypto_scrypt-ref.c'
            ],
            'conditions': [
                ['OS == "linux"', {
                    'link_settings': {
                        'libraries': [
                            '-lcrypto', #The openssl library (libcrypto)
                            '-lrt' #RealTime library
                        ],
                    },
                }]
            ],
        },
        {
            'target_name': 'scrypt_passwordhash',
            'type': 'static_library',
            'defines': [
                'HAVE_CONFIG_H'                
            ],
            'sources': [
                'src/passwordhash/scrypthash.c'
            ],
            'include_dirs' : [
                'scrypt-1.1.6/lib/util',
                'scrypt-1.1.6/lib/crypto',
                'scrypt-1.1.6'
            ],
            'dependencies': ['scrypt_lib'],
        },
        {
            'target_name': 'scrypt',
            'sources': [
                'scrypt_node.cc',
                'src/util/base64.cc'
            ],
            'dependencies': ['scrypt_lib','scrypt_passwordhash'],
        },
    ],
}
