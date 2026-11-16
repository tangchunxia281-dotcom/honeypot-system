-- ============================================
-- MySQL 归档维护脚本
-- 说明：
-- 1) schema.sql 负责主库与归档库表初始化
-- 2) 当前应用只对 SQLite 自动归档；MySQL 归档建议手工执行或挂定时 EVENT
-- 3) 不再依赖分区，避免与当前代码/表结构脱节
-- ============================================

USE honeypot_db;

CREATE DATABASE IF NOT EXISTS honeypot_archive
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS honeypot_archive.raw_request LIKE honeypot_db.raw_request;
CREATE TABLE IF NOT EXISTS honeypot_archive.session_track LIKE honeypot_db.session_track;
CREATE TABLE IF NOT EXISTS honeypot_archive.event_log LIKE honeypot_db.event_log;

DELIMITER $$

DROP PROCEDURE IF EXISTS sp_archive_before $$
CREATE PROCEDURE sp_archive_before(IN p_cutoff DATETIME)
BEGIN
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;

  INSERT IGNORE INTO honeypot_archive.raw_request (
      id, session_id, src_ip, method, path, query_string, headers, body,
      user_agent, referer, content_type, content_length, is_suspicious,
      threat_score, create_time
  )
  SELECT
      id, session_id, src_ip, method, path, query_string, headers, body,
      user_agent, referer, content_type, content_length, is_suspicious,
      threat_score, create_time
  FROM honeypot_db.raw_request
  WHERE create_time < p_cutoff;

  DELETE FROM honeypot_db.raw_request
  WHERE create_time < p_cutoff;

  INSERT IGNORE INTO honeypot_archive.session_track (
      id, session_id, src_ip, first_seen, last_seen, request_count,
      path_sequence, is_attacker, threat_level
  )
  SELECT
      id, session_id, src_ip, first_seen, last_seen, request_count,
      path_sequence, is_attacker, threat_level
  FROM honeypot_db.session_track
  WHERE last_seen < p_cutoff;

  DELETE FROM honeypot_db.session_track
  WHERE last_seen < p_cutoff;

  INSERT IGNORE INTO honeypot_archive.event_log (
      id, `timestamp`, source, severity, event_type, src_ip, session_id,
      tags, payload, raw_ref, raw_request_id, extra
  )
  SELECT
      id, `timestamp`, source, severity, event_type, src_ip, session_id,
      tags, payload, raw_ref, raw_request_id, extra
  FROM honeypot_db.event_log
  WHERE `timestamp` < p_cutoff;

  DELETE FROM honeypot_db.event_log
  WHERE `timestamp` < p_cutoff;

  COMMIT;
END $$

DELIMITER ;

-- 手工执行示例：
-- CALL sp_archive_before('2026-04-01 00:00:00');
--
-- 若希望由 MySQL 自己定时归档，可在确认拥有 EVENT 权限后执行下面这段：
--
-- SET GLOBAL event_scheduler = ON;
--
-- DELIMITER $$
-- DROP EVENT IF EXISTS ev_archive_hot_window $$
-- CREATE EVENT ev_archive_hot_window
-- ON SCHEDULE EVERY 1 DAY
-- STARTS TIMESTAMP(CURRENT_DATE, '01:10:00')
-- DO
-- BEGIN
--   CALL sp_archive_before(CURRENT_TIMESTAMP - INTERVAL 7 DAY);
-- END $$
-- DELIMITER ;
