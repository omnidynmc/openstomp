#include <config.h>

#include <string>

#include <stdarg.h>
#include <stdio.h>

#include <openframe/openframe.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "App.h"
#include "openstomp.h"

namespace openstomp {
  using namespace openframe::loglevel;

  const char *App::kPidFile	= "openstomp.pid";

  App::App(const std::string &prompt, const std::string &config) :
    super(prompt, config) {
    _stats = NULL;
  } // App::App

  App::~App() {
    delete _stats;
  } // App:~App

  void App::onInitializeSystem() { }
  void App::onInitializeConfig() { }
  void App::onInitializeCommands() { }
  void App::onInitializeDatabase() { }
  void App::onInitializeModules() { }

  void App::onInitializeThreads() {
    std::string source = app->cfg->get_string("app.stompstats.source", "openstomp");
    std::string instance = app->cfg->get_string("app.stompstats.instance", "prod");
    time_t update_interval = app->cfg->get_int("app.stompstats.interval", 300);
    std::string hosts = app->cfg->get_string("app.stompstats.hosts", "localhost:61613");
    std::string login = app->cfg->get_string("app.stompstats.login", "openstomp-stompstats");
    std::string passcode = app->cfg->get_string("app.stompstats.passcode", "openstomp-stompstats");
    int maxqueue = app->cfg->get_int("app.stompstats.maxqueue", 100);
    std::string dest = app->cfg->get_string("app.stompstats.destination", "/topic/stats");

    _stats = new stomp::StompStats(source,
                                   instance,
                                   update_interval,
                                   maxqueue,
                                   hosts,
                                   login,
                                   passcode,
                                   dest);

    _stats->set_elogger(&elog, "app");
    _stats->start();
  } // App::onInitializeThreads

  void App::onDeinitializeSystem() { }
  void App::onDeinitializeCommands() { }
  void App::onDeinitializeDatabase() { }
  void App::onDeinitializeModules() { }
  void App::onDeinitializeThreads() { }

  bool App::onRun() {
//    _consolef("*** %s started, version %s", _prompt.c_str(), VERSION);
   return false;
 } // App::onRun

  void App::rcvSighup() {
    LOG(LogNotice, << "### SIGHUP Received" << std::endl);
    elogger()->hup();
  } // App::rcvSighup
  void App::rcvSigusr1() {
    LOG(LogNotice, << "### SIGHUS1 Received" << std::endl);
  } // App::Sigusr1
  void App::rcvSigusr2() {
    LOG(LogNotice, << "### SIGUSR2 Received" << std::endl);
  } // App::Sigusr2
  void App::rcvSigint() {
    LOG(LogNotice, << "### SIGINT Received" << std::endl);
    set_done(true);
  } // App::rcvSigint
  void App::rcvSigpipe() {
    LOG(LogNotice, << "### SIGPIPE Received" << std::endl);
  } // App::rcvSigpipe

} // openstomp
