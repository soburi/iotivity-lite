#include "oc_ri.h"

class OCMethod {
public:
  enum {
    GET = OC_GET,
    POST =  OC_POST,
    PUT =  OC_PUT,
    DELETE =  OC_DELETE
  };

  OCMethod() {}
  operator oc_method_t() { return value; }
  oc_method_t& operator=(const oc_method_t& v) { value = v; return value; }
private:
  oc_method_t value;
};
