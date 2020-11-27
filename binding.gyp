{
  'target_defaults': {
    'configurations': {
      'Debug': {
        'defines': [ 'OC_DEBUG', 'DEBUG', '_DEBUG', 'V8_ENABLE_CHECKS' ],
      }
    }
  },
  'targets': [
    {
      'target_name': 'iotivity-lite-native',
      'sources': [
        'napi/src/iotivity_lite.cc',
        'napi/src/functions.cc',
        'napi/src/helper.cc',
        'api/c-timestamp/timestamp_compare.c',
        'api/c-timestamp/timestamp_format.c',
        'api/c-timestamp/timestamp_parse.c',
        'api/c-timestamp/timestamp_tm.c',
        'api/c-timestamp/timestamp_valid.c',
        'api/cloud/oc_cloud.c',
        'api/cloud/oc_cloud_apis.c',
        'api/cloud/oc_cloud_manager.c',
        'api/cloud/oc_cloud_rd.c',
        'api/cloud/oc_cloud_resource.c',
        'api/cloud/oc_cloud_store.c',
        'api/cloud/rd_client.c',
        'api/oc_base64.c',
        'api/oc_blockwise.c',
        'api/oc_buffer.c',
        'api/oc_client_api.c',
        'api/oc_clock.c',
        'api/oc_collection.c',
        'api/oc_core_res.c',
        'api/oc_discovery.c',
        'api/oc_endpoint.c',
        'api/oc_enums.c',
        'api/oc_helpers.c',
        'api/oc_introspection.c',
        'api/oc_main.c',
        'api/oc_mnt.c',
        'api/oc_network_events.c',
        'api/oc_rep.c',
        'api/oc_resource_factory.c',
        'api/oc_ri.c',
        'api/oc_server_api.c',
        'api/oc_session_events.c',
        'api/oc_swupdate.c',
        'api/oc_uuid.c',
        'deps/mbedtls/library/aes.c',
        'deps/mbedtls/library/aesni.c',
        'deps/mbedtls/library/arc4.c',
        'deps/mbedtls/library/asn1parse.c',
        'deps/mbedtls/library/asn1write.c',
        'deps/mbedtls/library/base64.c',
        'deps/mbedtls/library/bignum.c',
        'deps/mbedtls/library/blowfish.c',
        'deps/mbedtls/library/camellia.c',
        'deps/mbedtls/library/ccm.c',
        'deps/mbedtls/library/cipher.c',
        'deps/mbedtls/library/cipher_wrap.c',
        'deps/mbedtls/library/cmac.c',
        'deps/mbedtls/library/ctr_drbg.c',
        'deps/mbedtls/library/debug.c',
        'deps/mbedtls/library/des.c',
        'deps/mbedtls/library/dhm.c',
        'deps/mbedtls/library/ecdh.c',
        'deps/mbedtls/library/ecdsa.c',
        'deps/mbedtls/library/ecjpake.c',
        'deps/mbedtls/library/ecp.c',
        'deps/mbedtls/library/ecp_curves.c',
        'deps/mbedtls/library/entropy.c',
        'deps/mbedtls/library/entropy_poll.c',
        'deps/mbedtls/library/error.c',
        'deps/mbedtls/library/gcm.c',
        'deps/mbedtls/library/havege.c',
        'deps/mbedtls/library/hmac_drbg.c',
        'deps/mbedtls/library/md.c',
        'deps/mbedtls/library/md2.c',
        'deps/mbedtls/library/md4.c',
        'deps/mbedtls/library/md5.c',
        'deps/mbedtls/library/md_wrap.c',
        'deps/mbedtls/library/net_sockets.c',
        'deps/mbedtls/library/oid.c',
        'deps/mbedtls/library/padlock.c',
        'deps/mbedtls/library/pem.c',
        'deps/mbedtls/library/pk.c',
        'deps/mbedtls/library/pkcs11.c',
        'deps/mbedtls/library/pkcs12.c',
        'deps/mbedtls/library/pkcs5.c',
        'deps/mbedtls/library/pkparse.c',
        'deps/mbedtls/library/pkwrite.c',
        'deps/mbedtls/library/pk_wrap.c',
        'deps/mbedtls/library/platform.c',
        'deps/mbedtls/library/platform_util.c',
        'deps/mbedtls/library/ripemd160.c',
        'deps/mbedtls/library/rsa.c',
        'deps/mbedtls/library/rsa_internal.c',
        'deps/mbedtls/library/sha1.c',
        'deps/mbedtls/library/sha256.c',
        'deps/mbedtls/library/sha512.c',
        'deps/mbedtls/library/ssl_cache.c',
        'deps/mbedtls/library/ssl_ciphersuites.c',
        'deps/mbedtls/library/ssl_cli.c',
        'deps/mbedtls/library/ssl_cookie.c',
        'deps/mbedtls/library/ssl_srv.c',
        'deps/mbedtls/library/ssl_ticket.c',
        'deps/mbedtls/library/ssl_tls.c',
        'deps/mbedtls/library/threading.c',
        'deps/mbedtls/library/timing.c',
        'deps/mbedtls/library/version.c',
        'deps/mbedtls/library/version_features.c',
        'deps/mbedtls/library/x509.c',
        'deps/mbedtls/library/x509write_crt.c',
        'deps/mbedtls/library/x509write_csr.c',
        'deps/mbedtls/library/x509_create.c',
        'deps/mbedtls/library/x509_crt.c',
        'deps/mbedtls/library/x509_csr.c',
        'deps/mbedtls/library/xtea.c',
        'deps/tinycbor/src/cborencoder.c',
        'deps/tinycbor/src/cborencoder_close_container_checked.c',
        'deps/tinycbor/src/cborparser.c',
        'messaging/coap/coap.c',
        'messaging/coap/coap_signal.c',
        'messaging/coap/engine.c',
        'messaging/coap/observe.c',
        'messaging/coap/separate.c',
        'messaging/coap/transactions.c',
        'security/oc_acl.c',
        'security/oc_ael.c',
        'security/oc_audit.c',
        'security/oc_certs.c',
        'security/oc_cred.c',
        'security/oc_csr.c',
        'security/oc_doxm.c',
        'security/oc_keypair.c',
        'security/oc_obt.c',
        'security/oc_obt_certs.c',
        'security/oc_obt_otm_cert.c',
        'security/oc_obt_otm_justworks.c',
        'security/oc_obt_otm_randompin.c',
        'security/oc_pki.c',
        'security/oc_pstat.c',
        'security/oc_roles.c',
        'security/oc_sdi.c',
        'security/oc_sp.c',
        'security/oc_store.c',
        'security/oc_svr.c',
        'security/oc_tls.c',
        'util/oc_etimer.c',
        'util/oc_list.c',
        'util/oc_memb.c',
        'util/oc_mmem.c',
        'util/oc_process.c',
        'util/oc_timer.c',
      ],
      'include_dirs': [
        '.',
        'include',
        '..',
        'port',
        'messaging/coap',
        'util',
        'api',
        'deps/mbedtls/include',
        'deps/tinycbor/src',
        "<!@(node -p \"require('node-addon-api').include\")",
        "<!@(node -p \"require('napi-thread-safe-callback').include\")"
      ], 
      'conditions': [
        ['OS=="win"', {
          'include_dirs': [ 'port/windows' ],
          'sources': [
            'port/windows/abort.c',
            'port/windows/clock.c',
            'port/windows/ipadapter.c',
            'port/windows/mutex.c',
            'port/windows/network_addresses.c',
            'port/windows/random.c',
            'port/windows/storage.c',
            'port/windows/tcpadapter.c',
          ],
          'libraries': ['ws2_32.lib', 'iphlpapi.lib'],
          'defines': [
            'WIN32',
            '_CONSOLE',
            '_CRT_SECURE_NO_DEPRECATE',
	    '_HAS_EXCEPTIONS=1'
          ]
         }],
        ['OS=="linux"', {
          'include_dirs': [ 'port/linux' ],
          'sources': [
            'port/linux/ipadapter.c',
            'port/linux/tcpadapter.c',
            'port/linux/storage.c',
            'port/linux/abort.c',
            'port/linux/clock.c',
            'port/linux/random.c',
          ]
         }],
      ],
      'defines': ['OC_SERVER',
                  'OC_CLIENT',
                  'OC_SOFTWARE_UPDATE',
                  'OC_IPV4',
                  'OC_TCP',
                  'OC_CLOUD',
                  'OC_SECURITY',
                  'OC_PKI',
                  'OC_DYNAMIC_ALLOCATION',
                  'OC_IDD_API',
                  'OC_MNT',
		  'OC_COLLECTIONS_IF_CREATE',
                  '__OC_RANDOM',
      ],
      'dependencies': ["<!(node -p \"require('node-addon-api').gyp\")"],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ],
      'xcode_settings': {
        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
        'CLANG_CXX_LIBRARY': 'libc++',
        'MACOSX_DEPLOYMENT_TARGET': '10.7'
      },
      'msvs_settings': {
        'VCCLCompilerTool': {
	  'ExceptionHandling': 1,
	  'AdditionalOptions': [
                  '/wd26812', '/bigobj'
          ]
	}
      }
    }
  ]
}
