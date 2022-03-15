#ifndef OPENSTOMP_APP_H
#define OPENSTOMP_APP_H

#include <string>

#include <openframe/openframe.h>
#include <openframe/App/Application.h>
#include <stomp/StompStats.h>

#include "App_Log.h"

namespace openstomp {

/**************************************************************************
 ** General Defines                                                      **
 **************************************************************************/

/**************************************************************************
 ** Structures                                                           **
 **************************************************************************/
  class App_Exception : public openframe::OpenFrame_Exception {
    public:
      App_Exception(const std::string message) throw() : OpenFrame_Exception(message) {
      } // App_Exception

   private:
  }; // class App_Exception

  class App : public openframe::App::Application {
    public:
      typedef openframe::App::Application super;

      static const char *kPidFile;

      App(const std::string &, const std::string &);
      virtual ~App();

      // ### Public Members ###
      stomp::StompStats *stats() { return _stats; }

      // ### App_Abstract Virtuals ###
      void onInitializeSystem();
      void onInitializeConfig();
      void onInitializeCommands();
      void onInitializeDatabase();
      void onInitializeModules();
      void onInitializeThreads();

     void onDeinitializeSystem();
      void onDeinitializeCommands();
      void onDeinitializeDatabase();
      void onDeinitializeModules();
      void onDeinitializeThreads();

      void rcvSighup();
      void rcvSigusr1();
      void rcvSigusr2();
      void rcvSigint();
      void rcvSigpipe();

      bool onRun();

    protected:
    private:
      stomp::StompStats *_stats;
  }; // App

/**************************************************************************
 ** Macro's                                                              **
 **************************************************************************/

/**************************************************************************
 ** Proto types                                                          **
 **************************************************************************/
} // namespace openstomp

extern openstomp::App *app;
extern openframe::Logger elog;
#endif
