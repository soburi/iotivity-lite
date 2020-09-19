#include "oc_cred.h"

class OCCredType {
public:
  enum {
    NONE = OC_CREDTYPE_NULL,
    PSK = OC_CREDTYPE_PSK,
    CERT = OC_CREDTYPE_CERT,
  };

  OCCredType() {}
  operator oc_sec_credtype_t() { return value; }
  oc_sec_credtype_t& operator=(const oc_sec_credtype_t& v) { value = v; return value; }
private:
  oc_sec_credtype_t value;
};
