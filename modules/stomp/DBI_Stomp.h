#ifndef MODULE_DBI_STOMP_H
#define MODULE_DBI_STOMP_H

#include <map>
#include <string>

#include <mysql++.h>

#include <openframe/openframe.h>

namespace modstomp {
  using std::string;
  using std::map;
  using openframe::DBI;

/**************************************************************************
 ** General Defines                                                      **
 **************************************************************************/

/**************************************************************************
 ** Structures                                                           **
 **************************************************************************/

  class DBI_Stomp : public DBI {
    public:
      DBI_Stomp(const string &, const string &, const string &, const string &);
      virtual ~DBI_Stomp();

      // ### Type Definitions ###

      // ### Public Members ###
      const resultSizeType getCCById(const string &, resultType &);
      const resultSizeType dynamicEngineResults(const string &, const string &, resultType &);
      const resultSizeType getRelishById(const string &, resultType &);
      const resultSizeType getCCHistoryById(const string &, resultType &);
      const resultSizeType getCCLabelById(const string &, resultType &);
      const resultSizeType getCumulativeByCC(const string &, resultType &);
      const resultSizeType getSageReportPruneById(const string &, resultType &);
      const resultSizeType getLabelByName(const string &, resultType &);
      const resultSizeType getLabelByCCAndId(const string &, const string &, resultType &);
      const resultSizeType getHistoryByName(const string &, resultType &);
      const resultSizeType getHistoryByCCAndId(const string &, const string &, resultType &);
      const resultSizeType getCategoryByCCAndId(const string &, const string &, resultType &);
      const resultSizeType getTesByCCId(const string &, resultType &);
      const resultSizeType getWpromotedNameserverByHost(const string &, resultType &);
      const resultSizeType getWhiplashByIdOrHost(const string &, resultType &);
      const resultSizeType getSplashByIdOrHost(const string &, resultType &);
      const resultSizeType getRelishByIdOrSig(const string &, resultType &);
      const resultSizeType getBaysigByIdOrSig(const string &, resultType &);
      const resultSizeType getTaskState(resultType &);
      const simpleResultSizeType setWhiplashEvaluatedById(const string &);
      const simpleResultSizeType setSplashEvaluatedById(const string &);
      const simpleResultSizeType setWhitelistById(const string &);
      const simpleResultSizeType setLabelById(const string &, const string &, const string &);
      const simpleResultSizeType unsetLabelById(const string &, const string &);
      const simpleResultSizeType insertTesTriggerByCC(const string &, const string &);
      const resultSizeType dynamicQueryById(const string &, const string &, resultType &);
      const resultSizeType dynamicClearById(const string &, const string &);
      const resultSizeType dynamicClear(const string &);
      const simpleResultSizeType resetCCById(const string &);
      const simpleResultSizeType resetReporterById(const string &);
      const resultSizeType getReporterById(const string &, resultType &);
      const resultSizeType getReporterByIdOrName(const string &, resultType &);
      const resultSizeType getReportersByCC(const string &, resultType &);
      const resultSizeType getReporterIdByCCAndDays(const string &, const string &, resultType &);
      const resultSizeType getTrustwatchByReporterId(const string &, resultType &);

    protected:

    private:
      queryMapType _queryMap;
  }; // DBI_Stomp

/**************************************************************************
 ** Macro's                                                              **
 **************************************************************************/

/**************************************************************************
 ** Proto types                                                          **
 **************************************************************************/

} // namespace stomp

#endif
