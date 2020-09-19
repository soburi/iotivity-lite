#include "oc_cloud.h"

class OCCloudPrivisioningStatus {
public:
  enum {
    UNINITIALIZED = OC_CPS_UNINITIALIZED,
    READYTOREGISTER = OC_CPS_READYTOREGISTER,
    REGISTERING = OC_CPS_REGISTERING,
    REGISTERED = OC_CPS_REGISTERED,
    FAILED = OC_CPS_FAILED
  };

  OCCloudPrivisioningStatus() {}
  operator oc_cps_t() { return value; }
  oc_cps_t& operator=(const oc_cps_t& v) { value = v; return value; }
private:
  oc_cps_t value;
};
