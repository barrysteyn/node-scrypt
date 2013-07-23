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
            'defines': [ #This config file is custom generated for each POSIX OS
                'CONFIG_H_FILE="../config.h"',
            ],
            'link_settings': { #This is intended for all posix type environments except MAC
                'libraries': [
                    '-lcrypto', #The openssl library (libcrypto)
                    '-lrt', #RealTime library
                ],
            },
            'cflags' : [
                '-O2'
            ],
            'conditions': [
                [
                    'OS != "win"', { #Build config file for posix OS (i.e. not windows)
                        'actions' : [
                            {
                                'action_name' : 'configuration_script',
                                'inputs': [
                                    ''
                                ],
                                'outputs' : [
                                    'scrypt/config.h'
                                ],
                                'action' : ['scrypt/configuration/posixconfig'],
                                'message' : 'This may take a few seconds: Running customised posix configuration script to produce',
                            }
                        ],
                        'cflags' : [
                            '-w'
                        ],
                    },
                ],
                [
                    'OS == "mac"', { #Mr Mac, this section is specially for you :)
                        'link_settings': { 
                            'libraries': [ #Add dynamic lib
                                '-dynamiclib',
                            ],
                            'libraries!': [ #Remove lrt (not present in MAC)
                                '-lrt'
                            ]
                        },
                        'xcode_settings': {
                            'OTHER_CFLAGS': [
                                '-O2',
                            ]
                        },
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
            'conditions' : [
                [
                    'OS != "win"', {
                        'cflags' : [
                            '-w'
                        ],
                    },
                ],
            ],
        },
    ],
}
