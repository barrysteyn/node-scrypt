{
    'targets' : [
        {
            'target_name': 'scrypt_lib',
            'type': 'static_library',
            'include_dirs' : [
                'scrypt/scrypt-1.1.6',
                'scrypt/scrypt-1.1.6/lib/util',
                'scrypt/scrypt-1.1.6/lib/crypto',
                'scrypt/scrypt-1.1.6/lib/scryptenc'
            ],
            'sources': [
                'scrypt/scrypt-1.1.6/lib/scryptenc/scryptenc.c',
                'scrypt/scrypt-1.1.6/lib/util/memlimit.c',
                'scrypt/scrypt-1.1.6/lib/scryptenc/scryptenc_cpuperf.c',
                'scrypt/scrypt-1.1.6/lib/crypto/sha256.c',
                'scrypt/scrypt-1.1.6/lib/crypto/crypto_aesctr.c',
                'scrypt/scrypt-1.1.6/lib/crypto/crypto_scrypt-ref.c'
            ],
            # Default OS settings (includes Linux and all other unix type libs)
            'link_settings': {
                'libraries': [
                    '-lcrypto', #The openssl library (libcrypto)
                    '-lrt' #RealTime library
                ],
            },
            'defines': [
                'HAVE_CLOCK_GETTIME=1',
                'HAVE_LIBRT=1',
                'HAVE_STRUCT_SYSINFO=1',
                'HAVE_STRUCT_SYSINFO_MEM_UNIT=1',
                'HAVE_STRUCT_SYSINFO_TOTALRAM=1',
                'HAVE_SYSINFO=1',
                'HAVE_SYS_SYSINFO_H=1',
                'CONFIG_H_FILE="../config.h"',
            ],
            'cflags' : [
                '-O2'
            ],
            'conditions': [
                [
                    'OS == "mac"', {
                        'link_settings': {
                            'libraries': [
                                '-lcrypto',
                                '-dynamiclib',
                            ],
                        },
                        'defines': [
                            'HAVE_SYSCTL_HW_USERMEM=1',
                            'CONFIG_H_FILE="../config.h"'
                        ],
                        'xcode_settings': {
                            'OTHER_CFLAGS': [
                                '-O2'
                            ]
                        },
                    },
                ],
                [
                    'OS == "smartos"', {
                        'defines': [
                            'HAVE_LIBRT=1',
                            'HAVE_CLOCK_GETTIME=1',
                            'CONFIG_H_FILE="../config.h"'
                        ],
                    },
                ],
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
                'scrypt/scrypt-1.1.6/lib/util',
                'scrypt/scrypt-1.1.6/lib/crypto',
                'scrypt/scrypt-1.1.6/lib/scryptenc',
                'scrypt/scrypt-1.1.6'
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
