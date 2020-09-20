#include <oc_api.h>

typedef int (*fp_void_int)(void);
typedef void (*fp_void_void)(void);

class OCHandler : public oc_handler_t {
public:
  OCHandler( fp_void_int init_func
           , fp_void_void sigevent_func
           , fp_void_void regres_func
           , fp_void_void reqent_func)
/*
           : init(init_func)
           , signal_event_loop(sigevent_func)
#ifdef OC_SERVER
           , register_resource(regres_func)
#else
           , register_resource(NULL)
#endif
#ifdef OC_CLIENT
           , request_entry(reqent_func)
#else
           , request_entry(NULL)
#endif
*/
  {
    init = (fp_void_int)init_func;
    signal_event_loop = (fp_void_void)sigevent_func;
  }
};
