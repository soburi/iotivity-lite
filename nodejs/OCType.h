#include "oc_rep.h"

class OCType {
public:
  enum {
    NIL = OC_REP_NIL,
    INT = OC_REP_INT,
    DOUBLE = OC_REP_DOUBLE,
    BOOL = OC_REP_BOOL,
    BYTE_STRING = OC_REP_BYTE_STRING,
    STRING = OC_REP_STRING,
    OBJECT = OC_REP_OBJECT,
    ARRAY = OC_REP_ARRAY,
    INT_ARRAY = OC_REP_INT_ARRAY,
    DOUBLE_ARRAY = OC_REP_DOUBLE_ARRAY,
    BOOL_ARRAY = OC_REP_BOOL_ARRAY,
    BYTE_STRING_ARRAY = OC_REP_BYTE_STRING_ARRAY,
    STRING_ARRAY = OC_REP_STRING_ARRAY,
    OBJECT_ARRAY = OC_REP_OBJECT_ARRAY

  };

  OCType() {}
  operator oc_rep_value_type_t() { return value; }
  oc_rep_value_type_t& operator=(const oc_rep_value_type_t& v) { value = v; return value; }
private:
  oc_rep_value_type_t value;
};
