#ifndef __OPENSTOMP_OPENSTOMP_LOG
#define __OPENSTOMP_OPENSTOMP_LOG

#include <iostream>
#include <iomanip>
#include <string>

namespace openstomp {
  using std::string;
  using std::cout;
  using std::endl;

  class OpenStomp_Log {
    public:
      OpenStomp_Log(const string &ident) : _ident(ident) { }
      virtual ~OpenStomp_Log() { }

      virtual void log(const string &message) {
        cout << message << endl;
      } // log

      virtual void debug(const string &message) {
        cout << message << endl;
      } // log

      virtual void console(const string &message) {
        cout << message << endl;
      } // log

    protected:
      pthread_t _tid;
      string _ident;
    private:

  }; // OpenStomp_Log

} // openstomp

#endif
