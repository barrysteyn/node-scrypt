{
    'targets' : [
        {
            'target_name': 'scrypt_lib',
            'type': 'static_library',
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
                    'defines': [
                        'HAVE_CONFIG_H'                
                    ],
                    'cflags' : [
                        '-O2'
                    ]
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
                'scrypt-1.1.6/lib/scryptenc',
                'scrypt-1.1.6'
            ],
        },
        {
            'target_name': 'scrypt_node_boilerplate',
            'type': 'static_library',
            'defines': [
                'HAVE_CONFIG_H'                
            ],
            'sources': [
                'src/node-boilerplate/scrypt_node_async.cc',
                'src/node-boilerplate/scrypt_node_sync.cc',
                'src/node-boilerplate/scrypt_common.cc',
                'src/util/base64.cc',
            ],
            'include_dirs' : [
                'src/util',
                'src/passwordhash',
            ],
        },
        {
            'target_name': 'scrypt',
            'sources': [
                'scrypt_node.cc',
            ],
            'dependencies': ['scrypt_lib','scrypt_passwordhash','scrypt_node_boilerplate'],
        },
    ],
}
