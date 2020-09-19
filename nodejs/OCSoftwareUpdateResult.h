#include "oc_swupdate.h"

class OCSoftwareUpdateResult {
public:
  enum {
    IDLE = OC_SWUPDATE_RESULT_IDLE,
    SUCCESS = OC_SWUPDATE_RESULT_SUCCESS,
    LESS_RAM = OC_SWUPDATE_RESULT_LESS_RAM,
    LESS_FLASH = OC_SWUPDATE_RESULT_LESS_FLASH,
    CONN_FAIL = OC_SWUPDATE_RESULT_CONN_FAIL,
    SVV_FAIL OC_SWUPDATE_RESULT_SVV_FAIL,
    INVALID_URL = OC_SWUPDATE_RESULT_INVALID_URL,
    UPGRADE_FAIL OC_SWUPDATE_RESULT_UPGRADE_FAIL,
  };

  OCSoftwareUpdateResult() {}
  operator oc_swupdate_result_t() { return value; }
  oc_swupdate_result_t& operator=(const oc_swupdate_result_t& v) { value = v; return value; }
private:
  oc_swupdate_result_t value;
};
