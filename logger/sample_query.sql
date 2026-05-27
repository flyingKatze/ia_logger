-- =================================================================================================
-- Sample queries and dummy data for testing purposes only.
-- Do not run against production database.
-- ==================================================================================================

-- admin manual input for demo

-- password is `password`
-- change verified_location where youre located for testing to prevent triggering anomaly events
INSERT INTO "users" ("email", "employee_id", "personal_email", "password", "account_creation", "verified_location", "account_status", "key_totp", "activation_token", "token_expiry", "role", "notes", "changed_by")
VALUES ('email@company.com', '10000000', 'email@protonmail.com', '$2b$12$H2lX58/6.Iplsd8Oo4MuX.PqC0sB16DUBpK44U55cAp7./xQ4DR0O', '2026-03-28 15:07:57', 'Philippines', 'active', 'AN66BK4T5MTPES75HS3MZ53MN2K3YXT3', NULL, NULL, 'admin', 'root admin', 'admin');

INSERT INTO "users" ("email", "employee_id", "personal_email", "password", "account_creation", "verified_location", "account_status", "key_totp", "activation_token", "token_expiry", "role", "notes", "changed_by")
VALUES ('admin@company.com', '10000001', 'email@email.com', '$2b$12$H2lX58/6.Iplsd8Oo4MuX.PqC0sB16DUBpK44U55cAp7./xQ4DR0O', '2026-03-28 15:07:57', 'Philippines', 'active', 'AN66BK4T5MTPES75HS3MZ53MN2K3YXT3', NULL, NULL, 'admin', 'root admin', 'admin');

-- add admin schedule to prevent lockouts for testing
INSERT INTO "users_schedule" ("user_id", workdays, shift_start, shift_end, notes, changed_by)
VALUES ('1', 'MON,TUE,WED,THU,FRI,SAT,SUN', '00:00:00', '23:59:59', 'manual admin input', 'admin');

-- unlock admin
UPDATE "users"
SET "account_status" = 'unlocked'
WHERE "id" =  1;

--= TEMPLATES =--
UPDATE "users_schedule"
SET "workdays" = 'MON,TUE,WED,THU,FRI', "shift_start" = '13:00:00', "shift_end" = '20:00:00'
WHERE "id" = 12;

UPDATE "users"
SET "personal_email" = 'thejohnny_d@proton.me'
WHERE "id" = 2;

UPDATE "users"
SET "account_status" = 'inactive'
WHERE "id" = 8;

UPDATE "users"
SET "account_status" = 'active'
WHERE "id" = 1;

UPDATE "users"
SET "account_creation" = '2026-04-21 09:36:01'
WHERE "id" = 13;

-- user session manual input for demo
INSERT INTO "user_sessions" ("user_id", "email", "logged_in", "session_in", "country_in", "session_in_ip", "session_out", "country_out", "session_out_ip", "notes", "changed_by")
VALUES (2, 'email@email.com', 1, '2026-03-26 22:42:13', 'Philippines', '180.190.167.76', NULL, NULL, NULL, 'manual time in due to bug', 'admin');

-- for TEXT data type -- USE THIS FOR TESTING COUNT that involves time
SELECT COUNT("account_status") AS "count" FROM "accounts_logs" 
WHERE "user_id" = 3 AND ("account_status" = 'locked' OR "account_status" = 'flagged') AND "timestamp" BETWEEN datetime('now') AND datetime('now', '-24 hour')

SELECT COUNT("user_id") AS "count"  FROM "login_attempts_logs" WHERE "ip_address" = '180.190.167.116' AND "success" = 0 BETWEEN datetime('now') AND datetime('now', '-24 hours');

-- for INTEGER data type -- do not use this, db is using NUMERIC data type which is formatted as string when fetched from db
SELECT COUNT("user_id") AS "count"  FROM "login_attempts_logs" WHERE "ip_address" = '180.190.167.116' AND "success" = 0 AND "timestamp" >= unixepoch('now') - 345600;

--345600 = seconds -- 24*4(hours) * 60(minutes) * 60(seconds)

SELECT COUNT("ip_address") AS "COUNT"
FROM "login_attempts_logs"
WHERE "ip_address" = '180.190.167.116'
    AND "success" = 0
    AND "timestamp" BETWEEN datetime('now', '-72 hours') AND datetime('now');


SELECT COUNT("ip_address") AS "COUNT" FROM "login_attempts_logs" WHERE "ip_address" = '180.190.167.116' AND "success" = 0 AND "timestamp" BETWEEN datetime('now', '-72 hours') AND datetime('now');

SELECT COUNT("account_status") AS "count" FROM "accounts_logs" WHERE "user_id" = 1 AND "account_status" = 'locked' AND "timestamp" BETWEEN datetime('now', '-72 hours') AND datetime('now');


SELECT "account_status" FROM "accounts_logs" WHERE "user_id" = 5 AND "account_status" = 'active' LIMIT 1;

-- lockout count
SELECT COUNT("account_status") AS "count" FROM "accounts_logs" WHERE "user_id" = 8 AND ("account_status" = 'flagged' OR "account_status" = 'locked') AND "timestamp" BETWEEN datetime('now', '-96 hours') AND datetime('now');

-- lockout count ADMIN
SELECT COUNT("account_status") AS "count" FROM "accounts_logs" WHERE "user_id" = 1 AND ("account_status" = 'flagged' OR "account_status" = 'locked') AND "timestamp" BETWEEN datetime('now', '-72 hours') AND datetime('now');
