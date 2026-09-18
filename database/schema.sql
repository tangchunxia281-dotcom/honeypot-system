-- ============================================
-- 基于蜜罐技术的网络威胁捕获系统
-- MySQL 初始化脚本
-- 说明：
-- 1) 默认实验环境仍使用 SQLite，本文件仅用于切换到 MySQL 时初始化库表
-- 2) 按当前 db/ 访问层字段口径整理，不主动 DROP 现有表，避免误删数据
-- 3) 归档维护见 mysql_archive.sql
-- ============================================

CREATE DATABASE IF NOT EXISTS honeypot_db
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

CREATE DATABASE IF NOT EXISTS honeypot_archive
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE honeypot_db;

-- ============================================
-- 表1: geo_ip - IP 地理位置缓存表
-- ============================================
CREATE TABLE IF NOT EXISTS geo_ip (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键 ID',
    ip VARCHAR(45) NOT NULL COMMENT 'IP 地址',
    country VARCHAR(64) DEFAULT NULL COMMENT '国家',
    province VARCHAR(64) DEFAULT NULL COMMENT '省/州',
    city VARCHAR(64) DEFAULT NULL COMMENT '城市',
    latitude DECIMAL(10, 7) DEFAULT NULL COMMENT '纬度',
    longitude DECIMAL(10, 7) DEFAULT NULL COMMENT '经度',
    isp VARCHAR(128) DEFAULT NULL COMMENT '运营商/ISP',
    update_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (id),
    UNIQUE KEY uk_geo_ip_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='IP 地理位置缓存表';

-- ============================================
-- 表2: raw_request - 原始请求捕获表
-- ============================================
CREATE TABLE IF NOT EXISTS raw_request (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键 ID',
    session_id VARCHAR(64) DEFAULT NULL COMMENT '会话 ID',
    src_ip VARCHAR(45) NOT NULL COMMENT '源 IP',
    method VARCHAR(16) DEFAULT NULL COMMENT '请求方法',
    path VARCHAR(1024) DEFAULT NULL COMMENT '请求路径',
    query_string TEXT COMMENT 'URL 参数',
    headers MEDIUMTEXT COMMENT '请求头(JSON 字符串)',
    body MEDIUMTEXT COMMENT '请求体(截断存储)',
    user_agent VARCHAR(500) DEFAULT NULL COMMENT 'User-Agent',
    referer VARCHAR(500) DEFAULT NULL COMMENT 'Referer',
    content_type VARCHAR(100) DEFAULT NULL COMMENT 'Content-Type',
    content_length INT DEFAULT 0 COMMENT '内容长度',
    is_suspicious TINYINT(1) DEFAULT 0 COMMENT '是否可疑',
    threat_score INT DEFAULT 0 COMMENT '风险评分',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '捕获时间',
    PRIMARY KEY (id),
    KEY idx_raw_ip (src_ip),
    KEY idx_raw_session (session_id),
    KEY idx_raw_suspicious_score_time (is_suspicious, threat_score, create_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='原始请求捕获表';

-- ============================================
-- 表3: session_track - 会话追踪表
-- ============================================
CREATE TABLE IF NOT EXISTS session_track (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键 ID',
    session_id VARCHAR(64) NOT NULL COMMENT '会话 ID',
    src_ip VARCHAR(45) NOT NULL COMMENT '源 IP',
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '首次出现',
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '最后出现',
    request_count INT DEFAULT 1 COMMENT '请求次数',
    path_sequence TEXT COMMENT '路径序列',
    is_attacker TINYINT(1) DEFAULT 0 COMMENT '是否攻击者',
    threat_level VARCHAR(16) DEFAULT 'unknown' COMMENT '威胁等级',
    PRIMARY KEY (id),
    UNIQUE KEY uk_session_track_session_id (session_id),
    KEY idx_session_ip (src_ip),
    KEY idx_session_request_count (request_count),
    KEY idx_session_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='会话追踪表';

-- ============================================
-- 表4: event_log - 统一事件日志表
-- 与 db/event_logs.py 中 MySQL 建表口径保持一致
-- ============================================
CREATE TABLE IF NOT EXISTS event_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键 ID',
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '事件时间',
    source VARCHAR(16) NOT NULL COMMENT '事件来源：web/ssh/dashboard/system',
    severity VARCHAR(16) NOT NULL COMMENT '事件等级：low/medium/high/critical',
    event_type VARCHAR(64) NOT NULL COMMENT '事件类型',
    src_ip VARCHAR(64) DEFAULT '' COMMENT '来源 IP',
    session_id VARCHAR(64) DEFAULT '' COMMENT '会话 ID',
    tags TEXT COMMENT '标签(JSON 数组)',
    payload TEXT COMMENT '事件摘要(已脱敏/限长)',
    raw_ref VARCHAR(128) DEFAULT '' COMMENT '原始数据引用，如 raw_request:123',
    raw_request_id BIGINT DEFAULT NULL COMMENT '原始请求 ID，可空',
    extra TEXT COMMENT '扩展字段(JSON 字符串)',
    PRIMARY KEY (id),
    KEY idx_event_time (timestamp),
    KEY idx_event_source (source),
    KEY idx_event_severity (severity),
    KEY idx_event_type (event_type),
    KEY idx_event_ip (src_ip),
    KEY idx_event_raw_request (raw_request_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='统一事件日志表';

-- ============================================
-- 可选：初始化归档库表
-- 这样 mysql_archive.sql 就不需要重复维护表结构
-- ============================================
CREATE TABLE IF NOT EXISTS honeypot_archive.raw_request LIKE honeypot_db.raw_request;
CREATE TABLE IF NOT EXISTS honeypot_archive.session_track LIKE honeypot_db.session_track;
CREATE TABLE IF NOT EXISTS honeypot_archive.event_log LIKE honeypot_db.event_log;

-- 注意：
-- 1) geo_ip 作为缓存表，通常保留在主库即可，不单独做冷归档
-- 2) 若已有旧版本表结构，需要按实际库状态执行 ALTER TABLE 迁移，而不是重复导入本文件
