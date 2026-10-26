-- SQLAlchemy / Django / Hibernate / Rails generated queries
SELECT `auth_user`.`id`, `auth_user`.`username` FROM `auth_user` WHERE `auth_user`.`is_active` = true ORDER BY `auth_user`.`date_joined` DESC LIMIT 21;
SELECT COUNT(*) AS `__count` FROM `django_session` WHERE `django_session`.`expire_date` < '2024-01-01 00:00:00';
SELECT `django_content_type`.`id` FROM `django_content_type` WHERE (`django_content_type`.`app_label` = 'auth' AND `django_content_type`.`model` = 'user') LIMIT 21;
SELECT this_.id AS id1_0_0_, this_.name AS name2_0_0_ FROM employee this_ WHERE this_.id = ?;
SELECT e.id, e.name FROM employee e WHERE e.dept_id = ? ORDER BY e.name LIMIT ?, ?;
SELECT `users`.* FROM `users` WHERE `users`.`id` = 1 LIMIT 1 /* loading for inspect */;
SELECT 1 AS one FROM `users` WHERE `users`.`email` = BINARY 'a@b.c' LIMIT 1;
INSERT INTO `users` (`email`, `created_at`) VALUES ('a@b.c', '2024-01-01 00:00:00.123456');
UPDATE `users` SET `login_count` = COALESCE(`login_count`, 0) + 1 WHERE `users`.`id` = 1;
SELECT tbl.col FROM tbl -- trailing comment
WHERE tbl.id = 1;
/* leading block comment */ SELECT 1;
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql', 'sys');
SELECT @@SESSION.transaction_isolation, @@max_allowed_packet, @@lower_case_table_names, @@autocommit;
SELECT VERSION() AS v;
SELECT 1 + 1 AS two;
SELECT CONNECTION_ID();
SHOW VARIABLES LIKE 'sql_mode';
SHOW SESSION VARIABLES LIKE 'tx_isolation';
SHOW COLLATION;
SHOW CHARACTER SET;
SHOW GRANTS FOR 'app'@'%';
SHOW CREATE VIEW v;
SHOW FULL COLUMNS FROM users;
SHOW MASTER STATUS;
SHOW SLAVE STATUS;
