/**************************************************************************
 ** Copyright (C) 1999 Gregory A. Carter                                 **
 **                                                                      **
 ** This program is free software; you can redistribute it and/or modify **
 ** it under the terms of the GNU General Public License as published by **
 ** the Free Software Foundation; either version 1, or (at your option)  **
 ** any later version.                                                   **
 **                                                                      **
 ** This program is distributed in the hope that it will be useful,      **
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of       **
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        **
 ** GNU General Public License for more details.                         **
 **                                                                      **
 ** You should have received a copy of the GNU General Public License    **
 ** along with this program; if not, write to the Free Software          **
 ** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.            **
 **************************************************************************/

#include <list>
#include <fstream>
#include <queue>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <new>
#include <iostream>
#include <string>
#include <exception>

#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include <mysql++.h>

#include <openframe/openframe.h>

#include "App.h"
#include "Stomp.h"
#include "DBI_Stomp.h"

#include "stompCommands.h"

namespace modstomp {
  using namespace std;
  using namespace mysqlpp;
  using openframe::Result;

/**************************************************************************
 ** stdinSMSCDELIVERSM Class                                             **
 **************************************************************************/

  const int stdinSMSCDELIVERSM::Execute(COMMAND_ARGUMENTS) {
    string source, dest, message;

    if (ePacket->getArguments().size() < 3)
      return CMDERR_SYNTAX;

    // initialize variables
    source = ePacket->args()[0];
    dest = ePacket->args()[1];
    message = ePacket->args().getTrailing(2);

    ThreadMessage *tm = new ThreadMessage("deliver_sm", "test");
    tm->var->push_string("source", source);
    tm->var->push_string("dest", dest);
    tm->var->push_string("message", message);
    stomp->queue(tm);

    return CMDERR_SUCCESS;
  } // stdinSMSCDELIVERSM::Execute
} // namespace stomp
