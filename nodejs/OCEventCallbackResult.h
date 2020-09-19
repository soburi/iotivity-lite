#include "oc_ri.h"

class OCEventCallbackResult {
public:
  enum {
    GET = OC_GET,
    POST =  OC_POST,
    PUT =  OC_PUT,
    DELETE =  OC_DELETE
  };

  OCEventCallbackResult() {}
  operator oc_event_callback_retval_t() { return value; }
  oc_event_callback_retval_t& operator=(const oc_event_callback_retval_t& v) { value = v; return value; }
private:
  oc_event_callback_retval_t value;
};
