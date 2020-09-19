#include <oc_uuid.h>
class OCUuid : public oc_uuid_t {
public:
	void gen() { oc_gen_uuid(this); }
};
