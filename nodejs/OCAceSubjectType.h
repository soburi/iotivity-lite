#include "oc_acl.h"

class OCAceSubjectType {
public:
  enum {
    UUID = OC_SUBJECT_UUID,
    ROLE = OC_SUBJECT_ROLE,
    CONN = OC_SUBJECT_CONN
  };

  OCAceSubjectType() {}
  operator oc_ace_subject_type_t() { return value; }
  oc_ace_subject_type_t& operator=(const oc_ace_subject_type_t& v) { value = v; return value; }
private:
  oc_ace_subject_type_t value;
};
