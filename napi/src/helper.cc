#include "helper.h"

void oc_init_platform_helper(void* param) {
	callback_helper_t* helper = (callback_helper_t*)param;
	helper->function.Call({helper->value.Value()});
}
