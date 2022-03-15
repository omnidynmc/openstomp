#include <cassert>
#include <exception>
#include <iostream>
#include <new>
#include <string>

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stomp/StompStats.h>

#include "App.h"

using namespace std;
using openstomp::App;

openstomp::App *app;
openframe::Logger elog;

void usage(const char *prompt) {
  fprintf(stderr, "Usage: %s -c <config_file_path>\n", prompt);
  exit(1);
} // usage

int main(int argc, char **argv) {
  char *config = NULL;
  char *prompt = NULL;
  char ch;

  umask(077);

  // remember prompt
  if ((prompt = strrchr(argv[0], '/')))
    prompt++;
  else
    prompt = argv[0];

  // parse command line option
  bool daemonize = false;
  while ((ch = getopt(argc, argv, "vdc:")) != -1) {
    switch (ch) {
      case 'c':
        config = optarg;
        break;
      case 'd':
        daemonize = true;
        break;
      case 'v':
//        (void) version();
        exit(0);
        break;
      case '?':
      default:
        (void) usage(prompt);
        break;
    } // switch
  } // while

  argc -= optind;
  argv += optind;

  try {
    app = new openstomp::App(prompt, (config) ? config : "etc/openstomp.conf");
  } // try
  catch(bad_alloc xa) {
    assert(false);
  } // catch

  // write pid file
  if (!App::write_pid(App::kPidFile)) {
    std:cerr << "Could not write to PID file." << std::endl;
    exit(1);
  } // if

  elog.open("app", "logs/openstomp.stomp.log");
//  int loglevel = app->cfg->get_int("app.log.level", 7);
  int loglevel = 6;
  if (loglevel >= 0 && loglevel <= 7)
    elog.level("app", static_cast<openframe::loglevel::Level>(loglevel));
  else
    elog.level("app", openframe::loglevel::LogDebug);

  app->set_elogger(&elog, "app");

  app->start();
  if (daemonize) {
    while( !app->is_done() ) sleep(1);
  } // if
  else app->run();
  app->stop();

  delete app;

} // main
