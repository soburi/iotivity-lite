#include "oc_cred.h"

class OCCredUsage {
public:
  enum {
    NONE = OC_CREDUSAGE_NULL,
    TRUSTCA = OC_CREDUSAGE_TRUSTCA,
    IDENTITY_CRET = OC_CREDUSAGE_IDENTITY_CERT,
    ROLE_CERT = OC_CREDUSAGE_ROLE_CERT,
    MFG_TRUSTCA = OC_CREDUSAGE_MFG_TRUSTCA,
    MFG_CERT = OC_CREDUSAGE_MFG_CERT
  };

  OCCredUsage() {}
  operator oc_sec_credusage_t() { return value; }
  oc_sec_credusage_t& operator=(const oc_sec_credusage_t& v) { value = v; return value; }
private:
  oc_sec_credusage_t value;
};
