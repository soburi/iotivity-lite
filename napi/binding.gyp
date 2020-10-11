{
  'targets': [
    {
      'target_name': 'iotivity-lite-native',
      'sources': [ 'src/iotivity_lite.cc', 'src/structs.cc', 'src/functions.cc', 'src/binding.cc' ],
      'include_dirs': [".", "..", "../include", "../port", "../port/linux", "../util", "<!@(node -p \"require('node-addon-api').include\")"], 

      'conditions': [
        ['OS'=='linux', {
          "libraries": ['../../port/linux/libiotivity-lite-client-server.a'],
	  }
        ],
        ['OS'=='win', {
          "libraries": ['../../port/windows/vs2015/x64/Debug/Iotivity-lite.lib', 'ws2_32.lib'],
	  }
        ],
      ],
          "libraries": ['../../port/windows/vs2015/x64/Debug/Iotivity-lite.lib', 'ws2_32.lib', 'iphlpapi.lib'],

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
