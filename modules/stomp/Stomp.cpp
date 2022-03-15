#include <config.h>

#include <new>
#include <string>

#include <stdarg.h>
#include <stdio.h>

#include <openframe/openframe.h>
#include <openframe/stdinCommands.h>
#include <stomp/StompServer.h>
#include <openstats/StatsClient.h>

#include "App.h"
#include "Stomp.h"
//#include "DBI_Stomp.h"

#include "stomp.h"
#include "openstomp.h"

#include "stompCommands.h"

namespace modstomp {
  Stomp::Stomp() : _done(false) {
    //_dbi = NULL;

  } // Stomp::Stomp

  Stomp::~Stomp() {
  } // Stomp:~Stomp

  void Stomp::initializeSystem() {
    initializeCommands();
    initializeDatabase();
    initializeThreads();
    _consolef("*** Module Stomp: System Initialized");
  } // Stomp::initializeSystem

  void Stomp::initializeCommands() {
    openframe::CommandTree *command = app->command();
    command->addCommand("STOMP", "STDIN", "/STOMP", -1, openframe::Command::FLAG_CLEANUP, new openframe::stdinDTREE);

    _consolef("*** Module Stomp: Commands Initialized");
  } // Stomp::initializeCommands

  void Stomp::initializeDatabase() {
    try {
      //_dbi = new DBI_Stomp(MODULE_STOMP_SQL_DB, MODULE_STOMP_SQL_HOST, MODULE_STOMP_SQL_USER, MODULE_STOMP_SQL_PASS);
    } // try
    catch(std::bad_alloc xa) {
      assert(false);
    } // catch

    _consolef("*** Module Stomp: Database Initialized");
  } // Stomp::initializeDatabase

  void Stomp::deinitializeSystem() {
    done(true);
    deinitializeThreads();
    deinitializeCommands();
    deinitializeDatabase();
    _consolef("*** Module Stomp: System Deinitialized");
  } // Stomp::deinitializeSystem

  void Stomp::deinitializeThreads() {
    threadSetType::iterator ptr;
    pthread_t tid;

    while(!_stompThreads.empty()) {
      ptr = _stompThreads.begin();
      tid = (*ptr);
      _consolef("*** Module Stomp: Waiting for Thread %u to Deinitialized", tid);
      destroyThreadQ(tid);
      pthread_join(tid, NULL);
      _stompThreads.erase(tid);
    } // while

    _consolef("*** Module Stomp: Threads Denitialized");
  } // Stomp::deinitializeThreads

  void Stomp::initializeThreads() {
    pthread_t stompThread_tid;
    unsigned int i;
    unsigned int numStompThreads = app->cfg->get_int("module.stomp.threads", 1);

    // create our signal handling thread
    for(i=0; i < numStompThreads; i++) {
      pthread_create(&stompThread_tid, NULL, Stomp::StompThread, this);
      _consolef("*** Module Stomp: Started Stomp Thread %u", stompThread_tid);
      _stompThreads.insert(stompThread_tid);
      createThreadQ(stompThread_tid);
    } // for

    _consolef("*** Module Stomp: Threads Initialized");
  } // Stomp::initializeThreads

  void Stomp::deinitializeCommands() {
    app->command()->removeCommand("STDIN/STOMP");
    _consolef("*** Module Stomp: Commands Deinitialized");
  } // Stomp::initializeCommands

  void Stomp::deinitializeDatabase() {
    //if (_dbi) delete _dbi;

    _consolef("*** Module Stomp: Database Deinitialized");
  } // Stomp::deinitializeDatabase

  void *Stomp::StompThread(void *stomp) {
    Stomp *a = (Stomp *) stomp;
    stomp::StompServer *sserv;		// prod version
    int maxQueue = app->cfg->get_int("module.stomp.maxqueue", 100);
    int logStatsInterval = app->cfg->get_int("module.stomp.stats.interval", stomp::StompServer::kDefaultLogstatsInterval);
    unsigned int numThreads =  1; //a->numStompThreads()+1;

    time_t intval_logstats = app->cfg->get_int("module.stomp.timer.logstats", 60);
    size_t max_work = app->cfg->get_int("module.stomp.max_work", 10000);
    std::string bind_ip = app->cfg->get_string("app.bind_ip", "");

    sserv = new stomp::StompServer(MODULE_STOMP_PORT, MODULE_STOMP_MAX, bind_ip);

//    sserv->logger(new OpenFrame_Log("StompThread #" + StringTool::uint2string(numThreads)));

    sserv->set_elogger(&elog, "app");
    sserv->replace_stats( app->stats() );

    sserv->debug(false)
           .max_work(max_work)
           .intval_logstats(intval_logstats)
           .start();

    const time_t done_check_intval = 15;
    time_t last_done_check = time(NULL);
    while(1) {
      if (last_done_check < time(NULL) - done_check_intval) {
        if ( a->done() ) break;
        last_done_check = time(NULL);
      } // if

      bool didWork = sserv->run();

      if (!didWork) usleep(1000);
    } // while

    sserv->stop();

    delete sserv;

    return NULL;
  } // Stomp::StompThread
} // namespace stomp
