#include "oc_client_state.h"

class OCDiscoveryFlags {
public:
  enum {
    STOP = OC_STOP_DISCOVERY,
    CONTINUE = OC_CONTINUE_DISCOVERY
  };

  OCDiscoveryFlags() {}
  operator oc_discovery_flags_t() { return value; }
  oc_discovery_flags_t& operator=(const oc_discovery_flags_t& v) { value = v; return value; }
private:
  oc_discovery_flags_t value;
};
