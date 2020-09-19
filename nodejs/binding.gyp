{
  "targets": [
    {
      "target_name": "iotivity_lite",
      "sources": [ 
                   "iotivity_lite_wrap.cxx"
      ],
      "include_dirs": [ ".", "..", "../include", "../port", "../port/linux" ],
      "libraries": ['../../port/linux/libiotivity-lite-client-server.a']
    }
  ]
}
