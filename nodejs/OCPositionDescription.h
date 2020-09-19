#include "oc_enums.h"

class OCPositionDescription {
public:
  enum {
    TOP = OC_POS_TOP,
    BOTTOM = OC_POS_BOTTOM,
    LEFT = OC_POS_LEFT,
    RIGHT = OC_POS_RIGHT,
    CENTRE = OC_POS_CENTRE,
    TOPLEFT = OC_POS_TOPLEFT,
    BOTTOMLEFT = OC_POS_BOTTOMLEFT,
    CENTRELEFT = OC_POS_CENTRELEFT,
    CENTRERIGHT = OC_POS_CENTRERIGHT,
    BOTTOMRIGHT = OC_POS_BOTTOMRIGHT,
    TOPRIGHT = OC_POS_TOPRIGHT,
    TOPCENTRE = OC_POS_TOPCENTRE,
    BOTTOMCENTRE = OC_POS_BOTTOMCENTRE
  };

  OCPositionDescription() {}
  operator oc_pos_description_t() { return value; }
  oc_pos_description_t& operator=(const oc_pos_description_t& v) { value = v; return value; }
private:
  oc_pos_description_t value;
};
