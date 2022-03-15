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
 **************************************************************************
 $Id$
 **************************************************************************/

#include <fstream>
#include <string>
#include <queue>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <iostream>

#include <openframe/openframe.h>

#include "App.h"
#include "Stomp.h"

#include "stomp.h"
#include "openstomp.h"

namespace modstomp {
  using namespace openstomp;
  using namespace std;
  using openframe::ConfController;

extern "C" {

  /**********************
   ** Global Variables **
   **********************/

  Stomp *stomp;

  /******************
   ** Log Commands **
   ******************/

  /********************
   ** Initialization **
   ********************/

  /*****************
   ** Constructor **
   *****************/

  void module_constructor() {

    try {
      stomp = new modstomp::Stomp();
    } // try
    catch(bad_alloc xa) {
      assert(false);
    } // catch

    stomp->initializeSystem();

    return;
  } // module_constructor

  /****************
   ** Destructor **
   ****************/

  void module_destructor() {
    app->cfg->pop("module.stomp");

    // close listening sockets
    stomp->deinitializeSystem();
    delete stomp;

    return;
  } // module_destructor
} // extern
} // namespace stomp
