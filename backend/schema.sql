-- SAST engine database schema for the seven supported Python CWE rules.
-- Target: MySQL 8.0.16+ (enforced CHECK constraints).

CREATE DATABASE IF NOT EXISTS sast_engine
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE sast_engine;

CREATE TABLE IF NOT EXISTS cwe (
  cwe_id INT UNSIGNED NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  PRIMARY KEY (cwe_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cwe_list (
  list_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  list_name VARCHAR(100) NOT NULL,
  edition SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (list_id),
  UNIQUE KEY uq_cwe_list_name_edition (list_name, edition)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cwe_list_member (
  list_id BIGINT UNSIGNED NOT NULL,
  cwe_id INT UNSIGNED NOT NULL,
  rank_position SMALLINT UNSIGNED NOT NULL,
  score DECIMAL(6, 2) NULL,
  PRIMARY KEY (list_id, cwe_id),
  UNIQUE KEY uq_cwe_list_rank (list_id, rank_position),
  CONSTRAINT chk_cwe_list_rank_positive CHECK (rank_position > 0),
  CONSTRAINT fk_cwe_list_member_list
    FOREIGN KEY (list_id) REFERENCES cwe_list (list_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_cwe_list_member_cwe
    FOREIGN KEY (cwe_id) REFERENCES cwe (cwe_id)
    ON DELETE RESTRICT
) ENGINE=InnoDB;

-- Legacy rule metadata is retained for schema compatibility. The analyzer
-- executes versioned Python modules and does not load rules from this table.
CREATE TABLE IF NOT EXISTS detection_rule (
  rule_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  cwe_id INT UNSIGNED NOT NULL,
  rule_name VARCHAR(150) NOT NULL,
  rule_category ENUM('source', 'sink', 'sanitizer') NOT NULL,
  framework VARCHAR(32) NOT NULL DEFAULT 'python',
  match_type VARCHAR(32) NOT NULL,
  matcher VARCHAR(512) NOT NULL,
  configuration JSON NULL,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (rule_id),
  KEY ix_detection_rule_cwe_enabled (cwe_id, is_enabled),
  CONSTRAINT fk_detection_rule_cwe
    FOREIGN KEY (cwe_id) REFERENCES cwe (cwe_id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

INSERT INTO cwe (cwe_id, name) VALUES
  (78, 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)'),
  (79, 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)'),
  (89, 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)'),
  (352, 'Cross-Site Request Forgery (CSRF)'),
  (787, 'Out-of-bounds Write'),
  (862, 'Missing Authorization'),
  (918, 'Server-Side Request Forgery (SSRF)')
ON DUPLICATE KEY UPDATE name = VALUES(name);

-- Preserve a prior installation's list_id while changing its seeded list to
-- the focused Python starter set. Fresh installations simply insert it below.
UPDATE cwe_list
SET list_name = 'SAST Python Rule Starter Set', edition = 1
WHERE list_name = 'CWE Top 25 Most Dangerous Software Weaknesses'
  AND edition = 2025;

INSERT INTO cwe_list (list_name, edition)
VALUES ('SAST Python Rule Starter Set', 1)
ON DUPLICATE KEY UPDATE list_name = VALUES(list_name);

-- Replace this curated list's membership so rerunning the script converges
-- to the same seven entries. No official Top 25 ranks or scores are implied.
DELETE member
FROM cwe_list_member AS member
JOIN cwe_list AS list_entry ON list_entry.list_id = member.list_id
WHERE list_entry.list_name = 'SAST Python Rule Starter Set'
  AND list_entry.edition = 1;

INSERT INTO cwe_list_member (list_id, cwe_id, rank_position, score)
SELECT list_id, 79, 1, NULL FROM cwe_list
WHERE list_name = 'SAST Python Rule Starter Set' AND edition = 1;

INSERT INTO cwe_list_member (list_id, cwe_id, rank_position, score)
SELECT list_id, 89, 2, NULL FROM cwe_list
WHERE list_name = 'SAST Python Rule Starter Set' AND edition = 1;

INSERT INTO cwe_list_member (list_id, cwe_id, rank_position, score)
SELECT list_id, 78, 3, NULL FROM cwe_list
WHERE list_name = 'SAST Python Rule Starter Set' AND edition = 1;

INSERT INTO cwe_list_member (list_id, cwe_id, rank_position, score)
SELECT list_id, 918, 4, NULL FROM cwe_list
WHERE list_name = 'SAST Python Rule Starter Set' AND edition = 1;

INSERT INTO cwe_list_member (list_id, cwe_id, rank_position, score)
SELECT list_id, 787, 5, NULL FROM cwe_list
WHERE list_name = 'SAST Python Rule Starter Set' AND edition = 1;

INSERT INTO cwe_list_member (list_id, cwe_id, rank_position, score)
SELECT list_id, 352, 6, NULL FROM cwe_list
WHERE list_name = 'SAST Python Rule Starter Set' AND edition = 1;

INSERT INTO cwe_list_member (list_id, cwe_id, rank_position, score)
SELECT list_id, 862, 7, NULL FROM cwe_list
WHERE list_name = 'SAST Python Rule Starter Set' AND edition = 1;

CREATE TABLE IF NOT EXISTS scan_telemetry (
  scan_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scanned_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  selected_cwe_ids JSON NOT NULL,
  duration_ms INT UNSIGNED NOT NULL,
  source_count INT UNSIGNED NOT NULL,
  finding_count INT UNSIGNED NOT NULL,
  custom_finding_count INT UNSIGNED NOT NULL,
  custom_observation_count INT UNSIGNED NOT NULL,
  PRIMARY KEY (scan_id),
  KEY ix_scan_telemetry_scanned_at (scanned_at)
) ENGINE=InnoDB;

-- Legacy starter metadata only; runtime rule behavior is defined in Python.
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 79, 'flask.request.args source', 'source', 'flask', 'attribute', 'request.args', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 79 AND rule_name = 'flask.request.args source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 79, 'flask.request.form source', 'source', 'flask', 'attribute', 'request.form', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 79 AND rule_name = 'flask.request.form source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 79, 'django request.GET source', 'source', 'django', 'attribute', 'request.GET', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 79 AND rule_name = 'django request.GET source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 79, 'django request.POST source', 'source', 'django', 'attribute', 'request.POST', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 79 AND rule_name = 'django request.POST source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 79, 'Flask render_template_string sink', 'sink', 'flask', 'call', 'flask.render_template_string', JSON_OBJECT('tainted_argument_indices', JSON_ARRAY(0))
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 79 AND rule_name = 'Flask render_template_string sink');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 79, 'Django mark_safe sink', 'sink', 'django', 'call', 'django.utils.safestring.mark_safe', JSON_OBJECT('tainted_argument_indices', JSON_ARRAY(0))
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 79 AND rule_name = 'Django mark_safe sink');

INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 89, 'flask.request.args source', 'source', 'flask', 'attribute', 'request.args', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 89 AND rule_name = 'flask.request.args source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 89, 'flask.request.form source', 'source', 'flask', 'attribute', 'request.form', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 89 AND rule_name = 'flask.request.form source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 89, 'django request.GET source', 'source', 'django', 'attribute', 'request.GET', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 89 AND rule_name = 'django request.GET source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 89, 'django request.POST source', 'source', 'django', 'attribute', 'request.POST', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 89 AND rule_name = 'django request.POST source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 89, 'DB-API execute query sink', 'sink', 'python', 'call_suffix', 'execute', JSON_OBJECT('tainted_argument_indices', JSON_ARRAY(0), 'parameterized_query_safe', TRUE)
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 89 AND rule_name = 'DB-API execute query sink');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 89, 'Django QuerySet raw sink', 'sink', 'django', 'call_suffix', 'raw', JSON_OBJECT('tainted_argument_indices', JSON_ARRAY(0))
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 89 AND rule_name = 'Django QuerySet raw sink');

INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 78, 'flask.request.args source', 'source', 'flask', 'attribute', 'request.args', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 78 AND rule_name = 'flask.request.args source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 78, 'flask.request.form source', 'source', 'flask', 'attribute', 'request.form', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 78 AND rule_name = 'flask.request.form source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 78, 'django request.GET source', 'source', 'django', 'attribute', 'request.GET', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 78 AND rule_name = 'django request.GET source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 78, 'django request.POST source', 'source', 'django', 'attribute', 'request.POST', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 78 AND rule_name = 'django request.POST source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 78, 'os.system command sink', 'sink', 'python', 'call', 'os.system', JSON_OBJECT('tainted_argument_indices', JSON_ARRAY(0))
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 78 AND rule_name = 'os.system command sink');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 78, 'os.popen command sink', 'sink', 'python', 'call', 'os.popen', JSON_OBJECT('tainted_argument_indices', JSON_ARRAY(0))
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 78 AND rule_name = 'os.popen command sink');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 78, 'subprocess shell command sink', 'sink', 'python', 'call_suffix', 'run|Popen|call|check_call|check_output', JSON_OBJECT('tainted_argument_indices', JSON_ARRAY(0), 'required_keywords', JSON_OBJECT('shell', TRUE))
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 78 AND rule_name = 'subprocess shell command sink');

INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 918, 'flask.request.args source', 'source', 'flask', 'attribute', 'request.args', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 918 AND rule_name = 'flask.request.args source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 918, 'flask.request.form source', 'source', 'flask', 'attribute', 'request.form', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 918 AND rule_name = 'flask.request.form source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 918, 'django request.GET source', 'source', 'django', 'attribute', 'request.GET', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 918 AND rule_name = 'django request.GET source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 918, 'django request.POST source', 'source', 'django', 'attribute', 'request.POST', JSON_OBJECT()
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 918 AND rule_name = 'django request.POST source');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 918, 'requests outbound URL sink', 'sink', 'python', 'call_suffix', 'get|post|put|patch|delete|request', JSON_OBJECT('module_prefix', 'requests', 'tainted_argument_indices', JSON_ARRAY(0))
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 918 AND rule_name = 'requests outbound URL sink');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 918, 'urllib urlopen sink', 'sink', 'python', 'call', 'urllib.request.urlopen', JSON_OBJECT('tainted_argument_indices', JSON_ARRAY(0))
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 918 AND rule_name = 'urllib urlopen sink');
INSERT INTO detection_rule
  (cwe_id, rule_name, rule_category, framework, match_type, matcher, configuration)
SELECT 918, 'httpx outbound URL sink', 'sink', 'python', 'call_suffix', 'get|post|put|patch|delete|request', JSON_OBJECT('module_prefix', 'httpx', 'tainted_argument_indices', JSON_ARRAY(0))
WHERE NOT EXISTS (SELECT 1 FROM detection_rule WHERE cwe_id = 918 AND rule_name = 'httpx outbound URL sink');

