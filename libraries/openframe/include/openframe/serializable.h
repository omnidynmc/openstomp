#ifndef __LIBOPENFRAME_SERIALIZABLE_H
#define __LIBOPENFRAME_SERIALIZABLE_H

#include <iostream>

namespace openframe {

/**************************************************************************
 ** General Defines                                                      **
 **************************************************************************/

/**************************************************************************
 ** Structures                                                           **
 **************************************************************************/

  class serializable {
    public:
      virtual void serialize(std::ostream &os) const = 0;
  }; // class serializable

  std::ostream &operator<<(std::ostream &os, const serializable &s);
  std::ostream &operator<<(std::ostream &os, const serializable *s);

/**************************************************************************
 ** Macro's                                                              **
 **************************************************************************/

/**************************************************************************
 ** Proto types                                                          **
 **************************************************************************/

} // namespace openframe
#endif
