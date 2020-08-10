#include <iotivity-lite.h>

int app_init() {
  int ret = oc_init_platform("MyPhone", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Test Phone", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

void issue_requests() {
}

void signal_event_loop() {
}

void setup() {
  static const oc_handler_t handler = {app_init,
                                       signal_event_loop,
                                       issue_requests };

  oc_main_init(&handler);
}

void loop() {

}

