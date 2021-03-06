#ifndef __MODULE_STOMP_STOMPCOMMANDS_H
#define __MODULE_STOMP_STOMPCOMMANDS_H

#include <openframe/Command.h>

namespace modstomp {
  using openframe::Command;
  using openframe::CommandHandler;
  using openframe::Packet;

/**************************************************************************
 ** General Defines                                                      **
 **************************************************************************/

/**************************************************************************
 ** Structures                                                           **
 **************************************************************************/

CREATE_COMMAND(stdinSMSCDELIVERSM);
CREATE_COMMAND(stdinESMESUBMITSM);

/**************************************************************************
 ** Macro's                                                              **
 **************************************************************************/

/**************************************************************************
 ** Proto types                                                          **
 **************************************************************************/

}
#endif
