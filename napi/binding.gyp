{
  'targets': [
    {
      'target_name': 'iotivity-lite-native',
      'sources': [ 'src/iotivity_lite.cc', 'src/structs.cc' ],
      'include_dirs': [".", "..", "../include", "../port", "../port/linux", "<!@(node -p \"require('node-addon-api').include\")"], 
      "libraries": ['../../port/linux/libiotivity-lite-client-server.a'],
      'dependencies': ["<!(node -p \"require('node-addon-api').gyp\")"],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ],
      'xcode_settings': {
        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
        'CLANG_CXX_LIBRARY': 'libc++',
        'MACOSX_DEPLOYMENT_TARGET': '10.7'
      },
      'msvs_settings': {
        'VCCLCompilerTool': { 'ExceptionHandling': 1 },
      }
    }
  ]
}
