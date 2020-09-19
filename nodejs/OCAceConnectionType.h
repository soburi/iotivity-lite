#include "oc_acl.h"

class OCAceConnectionType {
public:
  enum {
    AUTH_CRYPT = OC_CONN_AUTH_CRYPT,
    ANON_CLEAR = OC_CONN_ANON_CLEAR,
  };

  OCAceConnectionType() {}
  //operator oc_ace_connection_type_t() { return value; }
  oc_ace_connection_type_t& operator=(const oc_ace_connection_type_t& v) { value = v; return value; }
private:
  oc_ace_connection_type_t value;
};
