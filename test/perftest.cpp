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
#include <stomp/StompPeer.h>

int main(int argc, char **argv) {
/*
  openframe::Fifo in;
  const char *buf = "COMMAND\n\
this is a test\n\
wheee!";

  in.add_charbuf(buf, strlen(buf) );

  std::string blah;
  in.next_line(blah);
  std::cout << blah.length() << " " << blah << std::endl;

  blah = "";
  std::cout << in.next_line(blah) << std::endl;
  std::cout << blah.length() << " " << blah << std::endl;

  blah = "";
  std::cout << in.next_bytes(2, blah) << std::endl;
  std::cout << blah.length() << " " << blah << std::endl;

  blah = "";
  std::cout << in.next_bytes(2, blah) << std::endl;
  std::cout << blah.length() << " " << blah << std::endl;

  exit(0);
*/


  stomp::StompPeer *peer = new stomp::StompPeer(0);

  const char *line = "SEND\n\
destination:/queue/feeds.aprs.is\n\
Content-Length:26\n\
\n\
abcdefghijklmnopqrstuvwxyz\0";
  const size_t len = strlen(line);


  const time_t stats_intval = 15;
  const time_t sleep_intval = 1000;

  time_t last_stats = time(NULL);
  size_t num = 0;

  for(size_t i=0; i < 1000000; i++) {
    peer->receive(line, len);

    stomp::StompFrame *frame;
    if (peer->next_frame(frame) ) frame->release();

    std::string ret;
    peer->transmit(ret);
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

  exit(0);
} // main
