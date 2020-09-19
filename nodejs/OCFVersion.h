#include "oc_endpoint.h"

class OCFVersion {
public:
  enum {
    //OCF_VER_1_0_0 = OCF_VER_1_0_0,
    //OIC_VER_1_1_0 = OIC_VER_1_1_0
  };

  OCFVersion() {}
  operator ocf_version_t() { return value; }
  ocf_version_t& operator=(const ocf_version_t& v) { value = v; return value; }
private:
  ocf_version_t value;
};
