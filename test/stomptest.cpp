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

#include <openframe/openframe.h>
#include <stomp/StompClient.h>

int main(int argc, char **argv) {
  stomp::StompClient *scli = new stomp::StompClient("localhost:61613", "stomptest", "stomptest");

  scli->set_connect_read_timeout(0);
  scli->start();

  const char *line = "abcdefghijklmnopqrstuvwxyz";
  const char *dest = "/queue/feeds.aprs.is";
  const time_t stats_intval = 15;
  const time_t sleep_intval = 200;

  time_t last_stats = time(NULL);
  size_t num = 0;

  while(true) {
    stomp::StompHeaders *headers = new stomp::StompHeaders("APRS-Created", openframe::stringify<time_t>(time(NULL)) );
    scli->send(dest, line, headers);
    num++;

    if (last_stats < time(NULL) - stats_intval) {
      time_t diff = time(NULL) - last_stats;
      double lps = double(num) / double(diff);
      std::cout << "lps=" << std::fixed << std::setprecision(2) << lps << std::endl;
      num = 0;
      last_stats = time(NULL);
    } // if
    usleep(sleep_intval);
  } // while

  scli->stop();
  exit(0);
} // main
