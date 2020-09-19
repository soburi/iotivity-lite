#include "oc_session_events.h"

class OCSessionState {
public:
  enum {
    CONNECTED = OC_SESSION_CONNECTED,
    DISCONNECTED = OC_SESSION_DISCONNECTED
  };

  OCSessionState() {}
  operator oc_session_state_t() { return value; }
  oc_session_state_t& operator=(const oc_session_state_t& v) { value = v; return value; }
private:
  oc_session_state_t value;
};
