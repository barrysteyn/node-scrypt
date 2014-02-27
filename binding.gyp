{
	'targets' : [
		{
			'target_name': 'scrypt_lib',
			'type' : 'static_library',
			'include_dirs' : [
				'scrypt/scrypt-1.1.6',
				'scrypt/scrypt-1.1.6/lib/util',
				'scrypt/scrypt-1.1.6/lib/crypto',
			],
			'sources': [
				'scrypt/scrypt-1.1.6/lib/util/memlimit.c',
				'scrypt/scrypt-1.1.6/lib/crypto/sha256.c',
				'scrypt/scrypt-1.1.6/lib/crypto/crypto_scrypt-sse.c',
			],
			'defines': [ #This config file is custom generated for each POSIX OS
				'CONFIG_H_FILE="../config.h"',
			],
			'conditions': [
				[
					'OS != "win"', { 
						#Configuration file is also built with this command
						'variables' : { 
							'libs' : '<!(scrypt/configuration/posixconfig)',
						},
						'include_dirs': [
							'scrypt/scrypt-1.1.6/lib/scryptenc',
							'<(node_root_dir)/deps/openssl/openssl/include',
						],
						'sources': [
							'scrypt/scrypt-1.1.6/lib/scryptenc/scryptenc.c',
							'scrypt/scrypt-1.1.6/lib/scryptenc/scryptenc_cpuperf.c',
							'scrypt/scrypt-1.1.6/lib/crypto/crypto_aesctr.c',
						],
						'libraries' : [
							'<@(libs)', #-lrt will be included here if it exists in the target OS
						],
					},
				],
			],
		},
		{
			'target_name': 'scrypt_wrapper',
			'type' : 'static_library',
			'defines': [
				'HAVE_CONFIG_H'				
			],
			'sources': [
				'src/util/salt.c',
				'src/scryptwrapper/keyderivation.c',
				'src/scryptwrapper/pickparams.c',
				'src/scryptwrapper/hash.c'
			],
			'include_dirs' : [
				'scrypt/scrypt-1.1.6/lib/util',
				'scrypt/scrypt-1.1.6/lib/crypto',
				'scrypt/scrypt-1.1.6/lib/scryptenc',
				'scrypt/scrypt-1.1.6',
				'src/util',
			],
			'dependencies': ['scrypt_lib'],
		},
		{
			'target_name': 'scrypt_node_boilerplate',
			'type' : 'static_library',
			'defines': [
				'HAVE_CONFIG_H'				
			],
			'sources': [
				'src/node-boilerplate/scrypt_params.cc',
				'src/node-boilerplate/scrypt_kdf.cc',
				'src/node-boilerplate/scrypt_hash.cc',
				'src/node-boilerplate/scrypt_verify.cc',
				'src/node-boilerplate/common.cc',
				'src/node-boilerplate/scrypt_error.cc',
				'src/node-boilerplate/scrypt_config_object.cc',
			],
			'include_dirs' : [
				'src/util',
				'src/scryptwrapper',
			],
			'dependencies': ['scrypt_wrapper'],
		},
		{
			'target_name': 'scrypt',
			'sources': [
				'scrypt_node.cc',
			],
			'dependencies': ['scrypt_node_boilerplate'],
		},
	],
}
