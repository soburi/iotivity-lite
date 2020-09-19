#include "oc_client_state.h"

class OCQos {
public:
  enum {
    HIGH = HIGH_QOS,
    LOW = LOW_QOS
  };

  OCQos() {}
  operator oc_qos_t() { return value; }
  oc_qos_t& operator=(const oc_qos_t& v) { value = v; return value; }
private:
  oc_qos_t value;
};
