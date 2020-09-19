#include "oc_cloud.h"

class OCCloudError {
public:
  enum {
    OK = CLOUD_OK,
    ERROR_RESPONSE = CLOUD_ERROR_RESPONSE,
    ERROR_CONNECT = CLOUD_ERROR_CONNECT,
    ERROR_REFRESH_ACCESS_TOKEN = CLOUD_ERROR_REFRESH_ACCESS_TOKEN,
  };

  OCCloudError() {}
  operator oc_cloud_error_t() { return value; }
  oc_cloud_error_t& operator=(const oc_cloud_error_t& v) { value = v; return value; }
private:
  oc_cloud_error_t value;
};
