#include "oc_ri.h"

class OCStatus {
public:
  enum {
    OK = OC_STATUS_OK,
    CREATED = OC_STATUS_CREATED,
    CHANGED = OC_STATUS_CHANGED,
    DELETED = OC_STATUS_DELETED,
    MODIFIED = OC_STATUS_NOT_MODIFIED,
    BAD_REQUEST = OC_STATUS_BAD_REQUEST,
    UNAUTHORIZED = OC_STATUS_UNAUTHORIZED,
    BAD_OPTION = OC_STATUS_BAD_OPTION,
    FORBIDDEN = OC_STATUS_FORBIDDEN,
    NOT_FOUND = OC_STATUS_NOT_FOUND,
    NOT_ALLOWED = OC_STATUS_METHOD_NOT_ALLOWED,
    NOT_ACCEPTABLE = OC_STATUS_NOT_ACCEPTABLE,
    REQUEST_ENTITY_TOO_LONG = OC_STATUS_REQUEST_ENTITY_TOO_LARGE,
    UNSUPPORTED_MEDIA_TYPE = OC_STATUS_UNSUPPORTED_MEDIA_TYPE,
    INITIAL_SERVER_ERROR = OC_STATUS_INTERNAL_SERVER_ERROR,
    NOT_IMPLEMENTED = OC_STATUS_NOT_IMPLEMENTED,
    BAD_GATEWAY = OC_STATUS_BAD_GATEWAY,
    SERVICE_UNAVAILABLE = OC_STATUS_SERVICE_UNAVAILABLE,
    GATEWAY_TIMEOUT = OC_STATUS_GATEWAY_TIMEOUT,
    PROXYING_NOT_SUPPORTED = OC_STATUS_PROXYING_NOT_SUPPORTED,
    __NUM_STATUS_CODES__ = __NUM_OC_STATUS_CODES__,
    IGNORE = OC_IGNORE,
    PING_TIMEOUT = OC_PING_TIMEOUT
  };

  OCStatus() {}
  operator oc_status_t() { return value; }
  oc_status_t& operator=(const oc_status_t& v) { value = v; return value; }
private:
  oc_status_t value;
};
