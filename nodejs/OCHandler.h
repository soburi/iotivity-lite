#include <oc_api.h>

typedef int (*init_fptr)(void);
typedef void (*sigevent_fptr)(void);
typedef void (*regres_fptr)(void);
typedef void (*reqent_fptr)(void);

class OCHandler : public oc_handler_t {
public:
  OCHandler( init_fptr init_func
           , sigevent_fptr sigevent_func
           , regres_fptr regres_func
           , reqent_fptr reqent_func)
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
    init = init_func;
    signal_event_loop = sigevent_func;
  }
};
