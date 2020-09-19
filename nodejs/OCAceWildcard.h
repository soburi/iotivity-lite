#include "oc_cred.h"

class OCAceWildcard {
public:
  enum {
    NO_WC          = OC_ACE_NO_WC,
    WC_ALL         = OC_ACE_WC_ALL,
    WC_ALL_SECURED = OC_ACE_WC_ALL_SECURED,
    WC_ALL_PUBLIC  = OC_ACE_WC_ALL_PUBLIC,
  };

  OCAceWildcard() {}
  operator oc_ace_wildcard_t() { return value; }
  oc_ace_wildcard_t& operator=(const oc_ace_wildcard_t& v) { value = v; return value; }
private:
  oc_ace_wildcard_t value;
};
