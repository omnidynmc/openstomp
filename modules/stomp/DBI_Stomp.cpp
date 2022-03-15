#include <new>
#include <string>
#include <map>

#include <mysql++.h>

#include "DBI_Stomp.h"

#include <openframe/openframe.h>

#include "config.h"

namespace modstomp {
  using namespace std;
  using openframe::StringTool;

  DBI_Stomp::DBI_Stomp(const string &db, const string &host, const string &user, const string &pass) : DBI(db, host, user, pass) {
    _queryMap["getCCById"] = "\
SELECT \
  t.id, \
  t.is_whitelisted, \
  t.isolation, \
  e.name AS engine, \
  e.long_desc, \
  t.confidence, \
  t.trust, \
  t.has_contention, \
  t.has_saturated, \
  t.content, \
  t.category, \
  c.label AS category_name, \
  t.trusted_reports, \
  t.trusted_revokes, \
  t.created, \
  t.last_seen, \
  t.last_updated, \
  (SELECT COUNT(*) FROM report r WHERE r.cc=t.id) AS num_reports, \
  (SELECT COUNT(*) FROM report r WHERE r.cc=t.id AND r.type=1) AS num_spam, \
  (SELECT COUNT(*) FROM report r WHERE r.cc=t.id AND r.type=2) AS num_legit, \
  (SELECT COUNT(*) FROM trigger_tes tt WHERE tt.cc=t.id) AS num_tes_triggers \
FROM \
  content_class t \
  LEFT JOIN engines e ON e.engine=t.isolation \
  LEFT JOIN category c ON c.id=t.category \
WHERE \
  t.id = %0q:id \
LIMIT 1 \
";

  _queryMap["getCCHistoryById"] = "\
SELECT \
  t.id, \
  t.cc, \
  t.op, \
  hd.description, \
  hd.value, \
  hd.notes, \
  t.oldvalue, \
  t.value AS newvalue, \
  t.ts AS created, \
  CONCAT('OP:', t.op, '|DSC:', hd.description, '|OLD:', t.oldvalue, '|NEW:', t.value, '|TS:', t.ts) AS combined \
FROM \
  cc_history t \
  LEFT JOIN cc_history_desc hd ON hd.id = t.op \
WHERE \
  t.cc = %0q:id \
ORDER BY t.ts DESC \
LIMIT 10 \
";

  _queryMap["getCumulativeByCC"] = "\
SELECT \
  t.cc, \
  t.block_confidence, \
  t.unblock_confidence, \
  t.trusted_blocks, \
  t.trusted_unblocks, \
  t.created, \
  t.last_updated \
FROM \
  cumulative_cc_info t \
WHERE \
  t.cc=%0q:id \
";

  _queryMap["getReporterById"] = "\
SELECT \
  t.id, \
  t.name, \
  t.origin, \
  t.registrar, \
  re.name AS registrar_name, \
  t.cramsha1, \
  t.trust, \
  t.trustgrp, \
  t.version, \
  v.cn, \
  v.cv, \
  v.vn, \
  t.last_seen, \
  t.created, \
  (SELECT COUNT(*) FROM report r WHERE r.reporter=t.id) AS num_reports \
FROM \
  reporter t \
  LEFT JOIN versions v ON v.id=t.version \
  LEFT JOIN registrar re ON re.id=t.registrar \
WHERE \
  t.id=%0q \
";

  _queryMap["getReporterMetaByReporterId"] = "\
SELECT \
  t.trust_ehash, \
  t.trust_baysig, \
  t.trust_whiplash, \
  t.trust_mishmash, \
  t.trust_relish, \
  t.trust_ultra, \
  t.trust_splash, \
  t.country, \
  t.location, \
  t.porigin, \
  t.last_updated, \
  t.penalizations, \
  t.last_penalty \
FROM \
  reporter_meta t \
WHERE \
  t.reporter=%0q:reporter_id \
";

  _queryMap["getSigcacheBySig"] = "\
SELECT \
  t.sig, \
  t.engine, \
  e.name AS engine_name, \
  t.reporter, \
  CASE t.type \
    WHEN 0 THEN '0 - NONE' \
    WHEN 1 THEN '1 - SPAM' \
    WHEN 2 THEN '2 - LEGIT' \
    WHEN 4 THEN '4 - PHISHING' \
    WHEN 6 THEN '6 - PHISHING AUTOBLOCK' \
    WHEN 7 THEN '7 - ISP NEWSLETTER' \
    WHEN 8 THEN '8 - SPAM IMPLICIT' \
    WHEN 9 THEN '9 - IS LEGIT IMPLICIT' \
    WHEN 10 THEN '10 - IS LEGIT AUTO' \
    WHEN 11 THEN '11 - IS LEGIT REPLY' \
    WHEN 12 THEN '12 - IS FRIEND ACCEPT' \
    WHEN 13 THEN '13 - IS FRIEND REJECT' \
    ELSE CONCAT(t.type, ' - ', 'UNKNOWN') \
  END AS type, \
  t.created \
FROM \
  sigcache t \
  LEFT JOIN engines e ON e.engine=t.engine \
WHERE \
  t.sig=%0q:sig \
";

  _queryMap["getTaskState"] = "\
SELECT \
  t.task, \
  t.last_id, \
  t.last_ts, \
  t.last_char \
FROM \
  task_state t \
";

  _queryMap["getReporterByIdOrName"] = "\
SELECT \
  t.id, \
  t.name, \
  t.origin, \
  t.registrar, \
  re.name AS registrar_name, \
  t.cramsha1, \
  t.trust, \
  t.trustgrp, \
  rmt.maxtrust, \
  rmt.last_updated AS maxtrust_last_updated, \
  t.version, \
  v.cn, \
  v.cv, \
  v.vn, \
  t.last_seen, \
  t.created, \
  (SELECT COUNT(*) FROM report r WHERE r.reporter=t.id) AS num_reports, \
  (SELECT COUNT(*) FROM report r WHERE r.reporter=t.id AND r.type=1) AS num_spam, \
  (SELECT COUNT(*) FROM report r WHERE r.reporter=t.id AND r.type=2) AS num_legit \
FROM \
  reporter t \
  LEFT JOIN versions v ON v.id=t.version \
  LEFT JOIN registrar re ON re.id=t.registrar \
  LEFT JOIN reporter_maxtrust rmt ON rmt.reporter=t.id \
WHERE \
  t.id=%0q \
  OR t.name LIKE %1q \
";

  _queryMap["getReportersByCC"] = "\
SELECT \
  t.reporter, \
  t.cc AS cc, \
  CASE t.type \
    WHEN 0 THEN '0 - NONE' \
    WHEN 1 THEN '1 - SPAM' \
    WHEN 2 THEN '2 - LEGIT' \
    WHEN 4 THEN '4 - PHISHING' \
    WHEN 6 THEN '6 - PHISHING AUTOBLOCK' \
    WHEN 7 THEN '7 - ISP NEWSLETTER' \
    WHEN 8 THEN '8 - SPAM IMPLICIT' \
    WHEN 9 THEN '9 - IS LEGIT IMPLICIT' \
    WHEN 10 THEN '10 - IS LEGIT AUTO' \
    WHEN 11 THEN '11 - IS LEGIT REPLY' \
    WHEN 12 THEN '12 - IS FRIEND ACCEPT' \
    WHEN 13 THEN '13 - IS FRIEND REJECT' \
    ELSE CONCAT(t.type, ' - ', 'UNKNOWN') \
  END AS type, \
  COUNT(*) AS num_reports, \
  (SELECT COUNT(*) FROM report WHERE report.reporter=t.reporter AND report.cc=t.cc AND report.type=1) AS num_spam, \
  (SELECT COUNT(*) FROM report WHERE report.reporter=t.reporter AND report.cc=t.cc AND report.type=2) AS num_legit, \
  r.name, \
  r.origin, \
  reg.name AS registrar_name, \
  r.cramsha1, \
  r.trust, \
  r.trustgrp, \
  rm.maxtrust, \
  v.cn, \
  v.cv, \
  v.vn, \
  r.last_seen, \
  t.created \
FROM \
  report t \
  LEFT JOIN reporter r ON r.id=t.reporter \
  LEFT JOIN reporter_maxtrust rm ON rm.reporter=r.id \
  LEFT JOIN versions v ON v.id=r.version \
  LEFT JOIN registrar reg ON reg.id=r.registrar \
WHERE \
  t.cc=%0q:cc \
GROUP BY t.reporter \
";

  _queryMap["getTrustwatchByReporterId"] = "\
SELECT \
  t.id, \
  c.comment, \
  t.adjuster_name, \
  t.trust_to, \
  t.trust_from, \
  t.trustgrp_to, \
  t.trustgrp_from, \
  t.maxtrust_to, \
  t.maxtrust_from, \
  t.created \
FROM \
  trustwatch_manual t \
  LEFT JOIN comments c ON c.id=t.comment_id \
WHERE \
  t.reporter_id=%0q:id \
ORDER BY t.created DESC \
LIMIT 5 \
";

  _queryMap["getSageReportPruneById"] = "\
SELECT \
  t.cc, \
  t.max_report_id, \
  t.method, \
  CONCAT('CC:', t.cc, '|RID:', t.max_report_id, '|METH:', t.method) AS combined \
FROM \
  sage_report_prune t \
WHERE \
  t.cc=%0q:id \
";

  _queryMap["getReportIdByCCAndDays"] = "\
SELECT \
  MIN(id) \
FROM \
  report \
WHERE \
  cc=%0q:cc \
  AND created > NOW() - INTERVAL %1:days DAY \
";

  _queryMap["getCCLabelById"] = "\
SELECT \
  t.id, \
  t.cc, \
  t.label, \
  cld.short_desc, \
  cld.long_desc, \
  t.param, \
  CONCAT('ID:', t.label, '|DSC:', cld.short_desc, '|PA:', t.param) AS combined \
FROM \
  cc_label t \
  LEFT JOIN cc_label_desc cld ON cld.label = t.label \
WHERE \
  t.cc = %0q:id \
";

  _queryMap["getLabelByCCAndId"] = "\
SELECT \
  t.id, \
  t.cc, \
  t.label, \
  cld.short_desc, \
  cld.long_desc, \
  t.param, \
  CONCAT('ID:', t.label, '|DSC:', cld.short_desc, '|PA:', t.param) AS combined \
FROM \
  cc_label t \
  LEFT JOIN cc_label_desc cld ON cld.label = t.label \
WHERE \
  t.cc = %0q:cc \
  AND t.label IN (%1:id) \
";

  _queryMap["getHistoryByCCAndId"] = "\
SELECT \
  t.id, \
  t.cc, \
  t.op, \
  hd.description, \
  hd.value, \
  hd.notes, \
  t.oldvalue, \
  t.value AS newvalue, \
  t.ts AS created, \
  CONCAT('OP:', t.op, '|DSC:', hd.description, '|OLD:', t.oldvalue, '|NEW:', t.value, '|TS:', t.ts) AS combined \
FROM \
  cc_history t \
  LEFT JOIN cc_history_desc hd ON hd.id = t.op \
WHERE \
  t.cc = %0q:cc \
  AND t.op IN (%1:id) \
";

  _queryMap["getCategoryByCCAndId"] = "\
SELECT \
  t.id, \
  t.cc, \
  t.category, \
  t.disposition, \
  t.created, \
  CONCAT('CA:', t.category, '|DIS:', t.disposition, '|CT:', t.created) AS combined \
FROM \
  cc_category t \
WHERE \
  t.cc = %0q:cc \
  AND t.category IN (%1:id) \
";

  _queryMap["getTesByCCId"] = "\
SELECT \
  t.id, \
  t.cc, \
  t.last_report, \
  t.created \
FROM \
  trigger_tes t \
WHERE \
  t.cc=%0q:id \
";

  _queryMap["getRelishById"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  rm.parser, \
  rm.sigsource, \
  rm.promotion, \
  rm.created \
FROM \
  relish t \
  LEFT JOIN relish_meta rm ON rm.id = t.meta \
WHERE \
  t.cc = %0q:id \
";

  _queryMap["getWpromotedNameserverByHost"] = "\
SELECT \
  1 \
FROM \
  wpromoted_nameservers \
WHERE \
  host=%0q:host \
";

  _queryMap["insertTesTriggerByCC"] = "\
INSERT INTO \
  trigger_tes \
  (cc, last_report) \
VALUES \
  (%0q:cc, %1q:last_report) \
";

  _queryMap["resetCCById"] = "\
UPDATE \
  content_class \
SET \
  is_whitelisted='N', \
  confidence=0.0, \
  trust=0.0, \
  has_contention='N', \
  has_saturated='N' \
WHERE \
  id=%0q:id \
";

  _queryMap["resetReporterById"] = "\
UPDATE \
  reporter t \
SET \
  t.trust='0.000', \
  t.trustgrp='1' \
WHERE \
  id=%0q:id \
";

  _queryMap["R2_EN_IMSIG"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  im.pipline, \
  im.version, \
  im.sigsource, \
  im.created \
FROM \
  imsig t \
  LEFT JOIN imsig_meta im ON im.id=t.meta \
WHERE \
  t.cc=%0q:id \
";

  _queryMap["R2_EN_BAYSIG"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc \
FROM \
  baysig t \
WHERE \
  t.cc=%0q:id \
";

  _queryMap["getBaysigByIdOrSig"] = _queryMap["R2_EN_BAYSIG"] + "\
  OR t.sig=%1q:sig \
";

  _queryMap["R2_EN_SWITCHBACK"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  sbm.sigsource, \
  sbm.created, \
  sbm.last_updated \
FROM \
  switchback t \
  LEFT JOIN switchback_meta sbm ON sbm.id=t.meta \
WHERE \
  t.cc=%0q:id \
";

  _queryMap["R2_EN_EASTBAYSIG"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  em.sigsource, \
  em.dictionary, \
  em.created \
FROM \
  eastbaysig t \
  LEFT JOIN eastbaysig_meta em ON em.id=t.meta \
WHERE \
  t.cc=%0q:id \
";

  _queryMap["R2_EN_ULTRA"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  um.is_retrievable, \
  um.is_truncated, \
  um.is_cnfs_retrievable, \
  um.extracted_content, \
  um.extracted_cnfs, \
  um.extracted_cnfs_time, \
  um.cloudmark, \
  um.md5, \
  um.first_source, \
  um.clamav, \
  um.avira, \
  um.mcafee, \
  um.clamav_time, \
  um.avira_time, \
  um.mcafee_time, \
  um.created, \
  um.last_updated \
FROM \
  ultra t \
  LEFT JOIN ultra_meta um ON um.id=t.meta \
WHERE \
  t.cc=%0q:id \
";

  _queryMap["R2_EN_RELISH"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  rm.parser, \
  rm.sigsource, \
  rm.promotion, \
  CASE rm.promotion \
    WHEN 0 THEN '0 - NONE' \
    WHEN 1 THEN '1 - PROMOTED' \
    WHEN 2 THEN '2 - DEMOTED' \
    WHEN 3 THEN '3 - RETRY' \
    WHEN 4 THEN '4 - DEFER TO WHIPLASH' \
    WHEN 5 THEN '5 - DEMOTED MANUAL' \
    ELSE CONCAT(rm.promotion, ' - ', 'UNKNOWN') \
  END AS promotion_desc, \
  rm.created \
FROM \
  relish t \
  LEFT JOIN relish_meta rm ON rm.id = t.meta \
WHERE \
  t.cc = %0q:id \
";

  _queryMap["getRelishByIdOrSig"] = _queryMap["R2_EN_RELISH"] + "\
  OR t.sig=%1q:sig \
";

  _queryMap["R2_EN_EHASH"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  em.sigsource, \
  em.degenerate, \
  em.truncated, \
  em.promotion, \
  em.last_updated, \
  em.created \
FROM \
  ehash t \
  LEFT JOIN ehash_meta em ON em.id = t.meta \
WHERE \
  t.cc = %0q:id \
";

  _queryMap["R2_EN_CHIPOTLE"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  cm.sigsource, \
  cm.rule, \
  cm.promotion, \
  cm.created, \
  cm.last_updated \
FROM \
  chipotle t \
  LEFT JOIN chipotle_meta cm ON cm.id=t.meta \
WHERE \
  t.cc=%0q:id \
";

  _queryMap["R2_EN_MISHMASH"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  mm.sigsource, \
  mm.promotion, \
  mm.last_updated, \
  mm.created \
FROM \
  mishmash t \
  LEFT JOIN mishmash_meta mm ON mm.id = t.meta \
WHERE \
  t.cc = %0q:id \
";

  _queryMap["R2_EN_CUNNING"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  cm.promotion, \
  cm.sigtrack, \
  cm.mode, \
  cm.sigsource, \
  cm.created \
FROM \
  cunning t \
  LEFT JOIN cunning_meta cm ON cm.id = t.meta \
WHERE \
  t.cc = %0q:id \
";

  _queryMap["R2_EN_SPLASH"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  INET_NTOA(sm.addr) AS addr, \
  sm.host, \
  sm.is_manual, \
  sm.promotion, \
  CASE sm.promotion \
    WHEN 0 THEN '0 - NONE' \
    WHEN 1 THEN '1 - PROMOTED' \
    WHEN 2 THEN '2 - DEMOTED' \
    WHEN 3 THEN '3 - RETRY' \
    WHEN 4 THEN '4 - PROMOTED DYNAMIC' \
    WHEN 5 THEN '5 - PROMOTED ROT CONTENT' \
    WHEN 6 THEN '6 - PROMOTED NODNS' \
    WHEN 7 THEN '7 - DEMOTED WHIPLASH' \
    WHEN 8 THEN '8 - PROMOTED WHIPLASH' \
    WHEN 10 THEN '10 - PROMOTED MANUAL' \
    WHEN 11 THEN '11 - DEMOTED WANT REPORTS' \
    WHEN 12 THEN '12 - PROMOTED MANUAL NOSNOW' \
    WHEN 13 THEN '13 - PROMOTED INVALID' \
    ELSE CONCAT(sm.promotion, ' - ', 'UNKNOWN') \
  END AS promotion_desc, \
  sm.geoip, \
  sm.reevaluate_promotion, \
  sm.created, \
  sm.last_updated \
FROM \
  splash t \
  LEFT JOIN splash_meta sm ON sm.id = t.meta \
WHERE \
  t.cc = %0q:id \
";

  _queryMap["getSplashByIdOrHost"] = _queryMap["R2_EN_SPLASH"] + "\
  OR sm.host=%1q:host \
  OR sm.addr=INET_ATON(%2q:ip) \
  OR t.sig=%3q:sig \
";

  _queryMap["R2_EN_WHIPLASH"] = "\
SELECT \
  t.id, \
  t.sig, \
  t.cc, \
  t.meta, \
  wm.host, \
  INET_NTOA(wm.addr) AS addr, \
  wm.promotion, \
  CASE wm.promotion \
    WHEN 0 THEN '0 - NONE' \
    WHEN 1 THEN '1 - PROMOTED' \
    WHEN 2 THEN '2 - DEMOTED' \
    WHEN 4 THEN '4 - PROMOTED PENDING' \
    WHEN 5 THEN '5 - WHOIS RETRY' \
    WHEN 6 THEN '6 - DEMOTED NOINFO' \
    WHEN 7 THEN '7 - PROMOTED SECOND ROUND' \
    WHEN 8 THEN '8 - PROMOTED REGISTRAR' \
    WHEN 10 THEN '10 - DNS RETRY' \
    WHEN 11 THEN '11 - PROMOTED METAINFO' \
    WHEN 12 THEN '12 - PROMOTED OLD' \
    WHEN 13 THEN '13 - PROMOTED OLD ALEXA' \
    WHEN 14 THEN '14 - PROMOTED ALEXA' \
    WHEN 15 THEN '15 - DEMOTED AUTO' \
    WHEN 16 THEN '16 - PROMOTED MANUAL' \
    WHEN 17 THEN '17 - PROMOTED BLOCK RATE' \
    ELSE CONCAT(wm.promotion, ' - ', 'UNKNOWN') \
  END AS promotion_desc, \
  wm.registered, \
  wm.sigs, \
  wm.whois_retry, \
  wm.whois_registrar, \
  wm.is_manual, \
  wm.has_rtol AS has_right_to_left, \
  wm.has_ltor AS has_left_to_right, \
  wm.reevaluate_promotion, \
  wm.created AS created_is_updated, \
  wm.last_updated AS last_updated_is_created \
FROM \
  whiplash t \
  LEFT JOIN whiplash_meta wm ON wm.id = t.meta \
WHERE \
  t.cc = %0q:id \
";

  _queryMap["getWhiplashByIdOrHost"] = _queryMap["R2_EN_WHIPLASH"] + "\
  OR wm.host=%1q:host \
  OR wm.addr=INET_ATON(%2q:ip) \
  OR t.sig=%3q:sig \
";

  _queryMap["setWhitelistById"] = "\
UPDATE \
  content_class t \
SET \
  t.is_whitelisted='Y' \
WHERE \
  t.id=%0q:id \
";

  _queryMap["setLabelById"] = "\
INSERT IGNORE INTO \
  cc_label \
  (cc, label, param) \
VALUES \
  (%0q:id, %1q:label, %2q:param) \
";

  _queryMap["unsetLabelById"] = "\
DELETE FROM \
  cc_label \
WHERE \
  cc=%0q:id \
  AND label=%1q:label \
";

  _queryMap["getLabelByNameOrId"] = "\
SELECT \
  t.label, \
  t.short_desc \
FROM \
  cc_label_desc t \
WHERE \
  t.short_desc LIKE %0q:name \
  OR t.label=%1q:label \
";

  _queryMap["getHistoryByNameOrId"] = "\
SELECT \
  t.description, \
  t.value, \
  t.notes \
FROM \
  cc_history_desc t \
WHERE \
  t.description LIKE %0q:name \
  OR t.id=%1q:id \
";

  _queryMap["setWhiplashEvaluatedById"] = "\
UPDATE \
  whiplash_meta t \
  LEFT JOIN whiplash w ON w.meta=t.id \
SET \
  t.reevaluate_promotion = NOW() + INTERVAL 1 WEEK, \
  t.promotion = 1 \
WHERE \
  w.cc=%0q:id \
";

  _queryMap["setSplashEvaluatedById"] = "\
UPDATE \
  splash_meta t \
  LEFT JOIN splash s ON s.meta=t.id \
SET \
  t.reevaluate_promotion = NOW() + INTERVAL 1 WEEK, \
  t.promotion = 1 \
WHERE \
  s.cc=%0q:id \
";

    _queryMap["clearCCLabels"] = "DELETE FROM cc_label WHERE cc=%0q:id";
    _queryMap["countCCLabels"] = "SELECT COUNT(*) FROM cc_label WHERE cc=%0q:id";

    _queryMap["clearCCHistory"] = "DELETE FROM cc_history WHERE cc=%0q:id";
    _queryMap["countCCHistory"] = "SELECT COUNT(*) FROM cc_history WHERE cc=%0q:id";

    _queryMap["clearCCTriggers"] = "DELETE FROM trigger_tes WHERE cc=%0q:id";
    _queryMap["countCCTriggers"] = "SELECT COUNT(*) FROM trigger_tes WHERE cc=%0q:id";

    _queryMap["clearCCCategory"] = "DELETE FROM cc_category WHERE cc=%0q:id";
    _queryMap["countCCCategory"] = "SELECT COUNT(*) FROM cc_category WHERE cc=%0q:id";

    _queryMap["clearCCSageReport"] = "DELETE FROM sage_report_prune WHERE cc=%0q:id";
    _queryMap["countCCSageReport"] = "SELECT COUNT(*) FROM sage_report_prune WHERE cc=%0q:id";

    _queryMap["clearTrust"] = "DELETE t, c FROM trustwatch_manual t, comments c WHERE t.reporter_id=%0q:id AND t.comment_id=c.id";
    _queryMap["countTrust"] = "SELECT COUNT(*) FROM trustwatch_manual t WHERE t.reporter_id=%0q:id";

    _queryMap["clearMaxtrust"] = "DELETE FROM reporter_maxtrust WHERE reporter=%0q:id";
    _queryMap["countMaxtrust"] = "SELECT COUNT(*) FROM reporter_maxtrust WHERE reporter=%0q:id";

    _queryMap["clearWpromotedNameservers"] = "TRUNCATE wpromoted_nameservers";
    _queryMap["countWpromotedNameservers"] = "SELECT COUNT(*) FROM wpromoted_nameservers";

  } // DBI_Stomp::DBI_Stomp

  DBI_Stomp::~DBI_Stomp() {
    _queryMap.clear();
  } // DBI_Stomp::~DBI_Stomp

  /*******************************************************************************
   ** Dynamic Query                                                             **
   *******************************************************************************/
  const DBI_Stomp::resultSizeType DBI_Stomp::dynamicEngineResults(const string &engine, const string &id, resultType &res) {
    // do we have a query for this engine?
    if (_queryMap.find(engine) == _queryMap.end())
      return 0;

    mysqlpp::Query query = _sqlpp->query(_queryMap[engine]);
    query.parse();

    try {
      res = query.store(id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::dynamicEngineResults

  const DBI_Stomp::resultSizeType DBI_Stomp::dynamicQueryById(const string &q, const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap[q]);
    query.parse();

    try {
      res = query.store(id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::dynamicQueryById

  const DBI_Stomp::resultSizeType DBI_Stomp::dynamicClearById(const string &q, const string &id) {
    mysqlpp::Query query = _sqlpp->query(_queryMap[string("clear") + q]);
    mysqlpp::Query query_c = _sqlpp->query(_queryMap[string("count") + q]);
    resultType res;
    resultSizeType num = 0;
    query.parse();
    query_c.parse();

    try {
      res = query_c.store(id);
      if (res.num_rows())
        num = atoi(res[0][0].c_str());
      query.execute(id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id).c_str());
      _consolef("%s", query_c.str(id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    return num;
  } // DBI_Stomp::dynamicClearById

  const DBI_Stomp::resultSizeType DBI_Stomp::dynamicClear(const string &q) {
    mysqlpp::Query query = _sqlpp->query(_queryMap[string("clear") + q]);
    mysqlpp::Query query_c = _sqlpp->query(_queryMap[string("count") + q]);
    resultType res;
    resultSizeType num = 0;
    query.parse();
    query_c.parse();

    try {
      res = query_c.store();
      if (res.num_rows())
        num = atoi(res[0][0].c_str());
      query.execute();
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str().c_str());
      _consolef("%s", query_c.str().c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    return num;
  } // DBI_Stomp::dynamicClear

  /*******************************************************************************
   ** Dynamic Query Wrappers                                                    **
   *******************************************************************************/
  const DBI_Stomp::resultSizeType DBI_Stomp::getTesByCCId(const string &id, resultType &res) {
    return dynamicQueryById("getTesByCCId", id, res);
  } // DBI_Stomp::getTesByCCId

  const DBI_Stomp::resultSizeType DBI_Stomp::getCCHistoryById(const string &id, resultType &res) {
    return dynamicQueryById("getCCHistoryById", id, res);
  } // DBI_Stomp::getCCHistoryById

  const DBI_Stomp::resultSizeType DBI_Stomp::getCCLabelById(const string &id, resultType &res) {
    return dynamicQueryById("getCCLabelById", id, res);
  } // DBI_Stomp::getCCLabelById

  const DBI_Stomp::resultSizeType DBI_Stomp::getRelishById(const string &id, resultType &res) {
    return dynamicQueryById("getRelishById", id, res);
  } // DBI_Stomp::getRelishById

  const DBI_Stomp::resultSizeType DBI_Stomp::getTrustwatchByReporterId(const string &id, resultType &res) {
    return dynamicQueryById("getTrustwatchByReporterId", id, res);
  } // DBI_Stomp::getTrustwatchByReporterId

  const DBI_Stomp::resultSizeType DBI_Stomp::getReporterById(const string &id, resultType &res) {
    return dynamicQueryById("getReporterById", id, res);
  } // DBI_Stomp::getRepoterById

  const DBI_Stomp::resultSizeType DBI_Stomp::getCumulativeByCC(const string &cc, resultType &res) {
    return dynamicQueryById("getCumulativeByCC", cc, res);
  } // DBI_Stomp::getRepoterById

  const DBI_Stomp::resultSizeType DBI_Stomp::getCCById(const string &id, resultType &res) {
    return dynamicQueryById("getCCById", id, res);
  } // DBI_Stomp::getCCById

  /*******************************************************************************
   ** Static Queries                                                            **
   *******************************************************************************/

  const DBI_Stomp::resultSizeType DBI_Stomp::getLabelByName(const string &name, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getLabelByNameOrId"]);
    query.parse();

    try {
      res = query.store(name, name);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(name, name).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getLabelByName

  const DBI_Stomp::resultSizeType DBI_Stomp::getTaskState(resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getTaskState"]);
    query.parse();

    try {
      res = query.store();
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str().c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getTaskState

  const DBI_Stomp::resultSizeType DBI_Stomp::getHistoryByName(const string &name, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getHistoryByNameOrId"]);
    query.parse();

    try {
      res = query.store(name, name);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(name, name).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getHistoryByName

  const DBI_Stomp::resultSizeType DBI_Stomp::getSageReportPruneById(const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getSageReportPruneById"]);
    query.parse();

    try {
      res = query.store(id, id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id, id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getSageReportPruneById

  const DBI_Stomp::resultSizeType DBI_Stomp::getLabelByCCAndId(const string &cc, const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getLabelByCCAndId"]);
    query.parse();

    try {
      res = query.store(cc, id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(cc, id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getLabelByCCAndId

  const DBI_Stomp::resultSizeType DBI_Stomp::getHistoryByCCAndId(const string &cc, const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getHistoryByCCAndId"]);
    query.parse();

    try {
      res = query.store(cc, id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(cc, id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getHistoryByCCAndId

  const DBI_Stomp::resultSizeType DBI_Stomp::getCategoryByCCAndId(const string &cc, const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getCategoryByCCAndId"]);
    query.parse();

    try {
      res = query.store(cc, id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(cc, id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getCategoryByCCAndId

  const DBI_Stomp::resultSizeType DBI_Stomp::getWpromotedNameserverByHost(const string &host, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getWpromotedNameserverByHost"]);
    query.parse();

    try {
      res = query.store(host);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(host).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getWpromotedNameserverByHost

  const DBI_Stomp::simpleResultSizeType DBI_Stomp::setWhiplashEvaluatedById(const string &id) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["setWhiplashEvaluatedById"]);
    simpleResultType res;
    query.parse();

    try {
      res = query.execute(id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.rows();
  } // DBI_Stomp::setWhiplashEvaluatedById

  const DBI_Stomp::simpleResultSizeType DBI_Stomp::setSplashEvaluatedById(const string &id) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["setSplashEvaluatedById"]);
    simpleResultType res;
    query.parse();

    try {
      res = query.execute(id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.rows();
  } // DBI_Stomp::setSplashEvaluatedById

  const DBI_Stomp::simpleResultSizeType DBI_Stomp::setWhitelistById(const string &id) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["setWhitelistById"]);
    simpleResultType res;
    query.parse();

    try {
      res = query.execute(id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.rows();
  } // DBI_Stomp::setWhitelistById

  const DBI_Stomp::simpleResultSizeType DBI_Stomp::setLabelById(const string &id, const string &label_id, const string &param) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["setLabelById"]);
    simpleResultType res;
    query.parse();

    try {
      res = query.execute(id, label_id, param);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id, label_id, param).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.rows();
  } // DBI_Stomp::setLabelById

  const DBI_Stomp::simpleResultSizeType DBI_Stomp::unsetLabelById(const string &id, const string &label_id) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["unsetLabelById"]);
    simpleResultType res;
    query.parse();

    try {
      res = query.execute(id, label_id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id, label_id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.rows();
  } // DBI_Stomp::unsetLabelById

  const DBI_Stomp::simpleResultSizeType DBI_Stomp::insertTesTriggerByCC(const string &cc, const string &last_report) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["insertTesTriggerByCC"]);
    simpleResultType res;
    query.parse();

    try {
      res = query.execute(cc, last_report);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(cc, last_report).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.rows();
  } // DBI_Stomp::insertTesTriggerByCC

  const DBI_Stomp::resultSizeType DBI_Stomp::getReporterIdByCCAndDays(const string &cc, const string &days, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getReportIdByCCAndDays"]);
    query.parse();

    try {
      res = query.store(cc, days);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(cc, days).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getReportIdByCCAndDays

  const DBI_Stomp::resultSizeType DBI_Stomp::getReportersByCC(const string &cc, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getReportersByCC"]);
    query.parse();

    try {
      res = query.store(cc);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(cc).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getRepotersByCC

  const DBI_Stomp::resultSizeType DBI_Stomp::getReporterByIdOrName(const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getReporterByIdOrName"]);
    query.parse();

    try {
      res = query.store(id, id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id, id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getRepoterByIdOrName

  const DBI_Stomp::resultSizeType DBI_Stomp::getWhiplashByIdOrHost(const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getWhiplashByIdOrHost"]);
    query.parse();

    try {
      res = query.store(id, id, id, id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id, id, id, id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getWhiplashByIdOrHost

  const DBI_Stomp::resultSizeType DBI_Stomp::getSplashByIdOrHost(const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getSplashByIdOrHost"]);
    query.parse();

    try {
      res = query.store(id, id, id, id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id, id, id, id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getSplashByIdOrHost

  const DBI_Stomp::resultSizeType DBI_Stomp::getRelishByIdOrSig(const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getRelishByIdOrSig"]);
    query.parse();

    try {
      res = query.store(id, id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id, id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getRelishByIdOrSig

  const DBI_Stomp::resultSizeType DBI_Stomp::getBaysigByIdOrSig(const string &id, resultType &res) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["getBaysigByIdOrSig"]);
    query.parse();

    try {
      res = query.store(id, id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id, id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.num_rows();
  } // DBI_Stomp::getBaysigByIdOrSig

  const DBI_Stomp::simpleResultSizeType DBI_Stomp::resetCCById(const string &id) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["resetCCById"]);
    simpleResultType res;
    query.parse();

    try {
      res = query.execute(id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.rows();
  } // DBI_Stomp::resetCCById

  const DBI_Stomp::simpleResultSizeType DBI_Stomp::resetReporterById(const string &id) {
    mysqlpp::Query query = _sqlpp->query(_queryMap["resetReporterById"]);
    simpleResultType res;
    query.parse();

    try {
      res = query.execute(id);
    } // try
    catch(mysqlpp::BadQuery e) {
      _consolef("%s", query.str(id).c_str());
      _consolef("*** SQL Error: #%d %s", e.errnum(), e.what());
    } // catch

    while(query.more_results())
      query.store_next();

    return res.rows();
  } // DBI_Stomp::resetReporterById
} // module stomp
