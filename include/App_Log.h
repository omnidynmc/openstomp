#ifndef OPENTEST_APP_LOG
#define OPENTEST_APP_LOG

#include "OpenStomp_Log.h"

namespace openstomp {

  class App_Log : public OpenStomp_Log {
    public:
      App_Log(const string &ident) : OpenStomp_Log(ident) { }
      virtual ~App_Log() { }

    protected:
    private:

  }; // OpenStomp_Log

} // openstomp

#endif
