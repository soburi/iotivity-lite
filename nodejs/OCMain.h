#include "oc_api.h"
#include "cstdio"
class OCMain {
public:
  int main_init(const oc_handler_t *handler) { printf("main_init"); return oc_main_init(handler); }
};
