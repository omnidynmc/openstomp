#ifndef __OPENSTOMP_OPENSTOMP_ABSTRACT_H
#define __OPENSTOMP_OPENSTOMP_ABSTRACT_H

#include <string>

#include <stdio.h>
#include <stdarg.h>

#include "OpenStomp_Log.h"

namespace openstomp {
  using std::string;

/**************************************************************************
 ** General Defines                                                      **
 **************************************************************************/

#define OPENTESTLOG_MAXBUF	1024

/**************************************************************************
 ** Structures                                                           **
 **************************************************************************/

  class OpenStomp_Exception : public std::exception {
    public:
      OpenStomp_Exception(const string message) throw() {
        if (!message.length())
          _message = "An unknown message exception occured.";
        else
          _message = message;
      } // OpenAbstract_Exception

      virtual ~OpenStomp_Exception() throw() { }
      virtual const char *what() const throw() { return _message.c_str(); }

      const char *message() const throw() { return _message.c_str(); }

    private:
      string _message;                    // Message of the exception error.
  }; // class OpenStomp_Exception

  class OpenStomp_Abstract {
    public:
      OpenStomp_Abstract() { _logger = new OpenStomp_Log("Abstract"); }
      virtual ~OpenStomp_Abstract() {
        if (_logger != NULL)
          delete _logger;
      } // OpenStomp_Abstract

      void logger(OpenStomp_Log *logger) {
        if (_logger != NULL)
          delete _logger;
        _logger = logger;
      } // logger

    protected:
      void _logf(const char *writeFormat, ...) {
        char writeBuffer[OPENTESTLOG_MAXBUF + 1] = {0};
        va_list va;

        va_start(va, writeFormat);
        vsnprintf(writeBuffer, sizeof(writeBuffer), writeFormat, va);
        va_end(va);

        _log(writeBuffer);
      } // log

    void _debugf(const char *writeFormat, ...) {
        char writeBuffer[OPENTESTLOG_MAXBUF + 1] = {0};
        va_list va;

        va_start(va, writeFormat);
        vsnprintf(writeBuffer, sizeof(writeBuffer), writeFormat, va);
        va_end(va);

        _debug(writeBuffer);
      } // _debugf

      void _consolef(const char *writeFormat, ...) {
        char writeBuffer[OPENTESTLOG_MAXBUF + 1] = {0};
        va_list va;

        va_start(va, writeFormat);
        vsnprintf(writeBuffer, sizeof(writeBuffer), writeFormat, va);
        va_end(va);

        _console(writeBuffer);
      } // _consolef

      virtual void _log(const string &message) {
        _logger->log(message);
      } // _log

      virtual void _debug(const string &message) {
        _logger->debug(message);
      } // _debug

      virtual void _console(const string &message) {
        _logger->console(message);
      } // _console

      // ### Variables ###
      OpenStomp_Log *_logger;

    private:

  }; // OpenStomp_Abstract

/**************************************************************************
 ** Macro's                                                              **
 **************************************************************************/

/**************************************************************************
 ** Proto types                                                          **
 **************************************************************************/


} // openstomp

#endif
