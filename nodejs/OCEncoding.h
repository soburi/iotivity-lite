#include "oc_cred.h"

class OCEncoding {
public:
  enum {
    UNSUPPORTED = OC_ENCODING_UNSUPPORTED,
    BASE64 = OC_ENCODING_BASE64,
    RAW = OC_ENCODING_RAW,
    PEM = OC_ENCODING_PEM,
    HANDLE = OC_ENCODING_HANDLE
  };

  OCEncoding() {}
  operator oc_sec_encoding_t() { return value; }
  oc_sec_encoding_t& operator=(const oc_sec_encoding_t& v) { value = v; return value; }
private:
  oc_sec_encoding_t value;
};
