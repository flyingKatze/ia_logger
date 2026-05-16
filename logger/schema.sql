-- users table represents any employee
CREATE TABLE "users" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "email" TEXT NOT NULL UNIQUE, -- work email
    "employee_id" TEXT NOT NULL, -- for logistics
    "personal_email" TEXT NOT NULL UNIQUE, -- receives tokens
    "password" TEXT NOT NULL,
    "account_creation" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "verified_location" TEXT NULL, -- where user is based in, very rarely an employee moves to a different country and work with the system. most international business trips are delegation, conferences, etc. this guards any access from foreign IP addresses
    "account_status" TEXT NOT NULL CHECK("account_status" IN ('flagged', 'locked', 'unlocked', 'active', 'inactive', 'terminated')),
    "key_totp" TEXT NOT NULL, -- totp validator
    "activation_token" TEXT, -- hashed like password
    "token_expiry" NUMERIC,
    "role" TEXT NOT NULL DEFAULT 'user' CHECK("role" IN ('admin', 'user')),
    "notes" TEXT NOT NULL DEFAULT "No notes were added.", -- logs, documentation for any changes made
    "changed_by" TEXT NOT NULL -- who made the changes, paper trailing
);
-- does not include batch scheduling or other time management like breaks, lunches, overtimes or legally inconsistent schedules, at least for python, which is out of scope but can be done in the future if developed or optimized
CREATE TABLE "users_schedule" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "workdays" TEXT NOT NULL DEFAULT "MON,TUE,WED,THU,FRI", -- MON, TUE, WED, THU, FRI, SAT, SUN 
    "shift_start" NUMERIC NOT NULL DEFAULT '08:00:00' CHECK(shift_start GLOB '[0-2][0-9]:[0-5][0-9]:[0-5][0-9]'),
    "shift_end" NUMERIC NOT NULL DEFAULT '17:00:00' CHECK(shift_end GLOB '[0-2][0-9]:[0-5][0-9]:[0-5][0-9]'),
    "notes" TEXT NOT NULL DEFAULT "No notes were added.",
    "changed_by" TEXT NOT NULL,

    FOREIGN KEY("user_id") REFERENCES "users"("id")
);
-- records IP during logins and out, does not auto calculate total time user an employee spent per day working (for pay)
CREATE TABLE "user_sessions" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "employee_id" TEXT NOT NULL, -- added for convience as option to show employee ID instead of email  in case of presenting the data to the stakeholders
    "email" TEXT NOT NULL,
    "session_in" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "session_out" NUMERIC NULL,
    "country_in" TEXT NOT NULL, 
    "country_out" TEXT NULL, 
    "session_in_ip" TEXT NOT NULL,
    "session_out_ip" TEXT NULL,
    "notes" TEXT NOT NULL DEFAULT "No notes were added.",
    "changed_by" TEXT NOT NULL,

    FOREIGN KEY("user_id") REFERENCES "users"("id")
);
-- logs all login attempts, different to table loggers.
CREATE TABLE "login_attempts_logs" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "email" TEXT NOT NULL,
    "ip_address" TEXT NOT NULL,
    "country" TEXT NOT NULL,
    "success" INTEGER NOT NULL CHECK("success" IN (0, 1)),
    "notes" TEXT NOT NULL DEFAULT "No notes were added.",
    "timestamp" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY("user_id") REFERENCES "users"("id")
);
-- logs unusual events that may point to attempts of breaching or account take overs, an independent table like login_attempts_logs which triggers an account lock
CREATE TABLE "security_events_logs" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL, -- user id of compromised account
    "anomaly" TEXT NOT NULL
        CHECK("anomaly" IN ('too_many_failed_attempts', 'inconsistent_ip', 'new_country_login', 'unusual_time', 'credential_stuffing')), -- consecutive failed attempts, new/unusual ip, geoloc, outside normal login hours, same ip with failed login attempts hitting multiple accounts
    "malicious_ip" TEXT, -- fill for credential stuffing
    "detected_location" TEXT, -- country location of the login attempt
    "notes" TEXT NOT NULL DEFAULT "No notes were added.", -- additional notes regarding anomaly
    "timestamp" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY("user_id") REFERENCES "users"("id")
);
-- where trusted IPs are recorded to add security guarding on IP addresses accessing the system
CREATE TABLE "trusted_networks" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "label" TEXT, -- admin workstations, device ips, etc
    "ip_range" TEXT,
    "trust_level" TEXT,
    "added_by" INTEGER NOT NULL,
    "time_added" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "is_active" INTEGER NOT NULL CHECK("is_active" IN (0, 1)),

    FOREIGN KEY("added_by") REFERENCES "users"("id")
);

-- list of blacklisted personal emails and ip addresses
CREATE TABLE "blacklist" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "ip_address" TEXT,
    "reason" TEXT NOT NULL,
    "added_by" TEXT NOT NULL,
    "time_added" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "action_done_by" INTEGER,

    FOREIGN KEY("action_done_by") REFERENCES "users"("id")
);
-- totally independent table. shortlive codes to guard against reuse of tokens in the same valid window
CREATE TABLE "used_totps" (
    "user_id" INTEGER NOT NULL,
    "otp_code" TEXT NOT NULL,
    "time_added" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY("user_id") REFERENCES "users"("id")
);

-- ------------------------------------------------------------------
-- LOGGERS (for triggers)
-- ---------------------------------------------------------------
-- tracks changes from users table -- to record deletions and tenure
CREATE TABLE "users_logs" ( 
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "action" TEXT NOT NULL CHECK("action" IN ('delete', 'update', 'insert')), -- any changes made
    "personal_email" TEXT NOT NULL, -- in case of personal email changes
    "password" TEXT NOT NULL,
    "account_creation" NUMERIC NOT NULL, -- in any case the tenure is edited/altered
    "verified_location" TEXT,
    "account_status" TEXT NOT NULL,
    "activation_token" TEXT,
    "token_expiry" NUMERIC,
    "role" TEXT NOT NULL CHECK("role" IN ('admin', 'user')),
    "notes" TEXT NOT NULL DEFAULT "No notes were added.", -- tracks all notes if any
    "changed_by" TEXT NOT NULL,
    "timestamp" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- records any changes made on users_schedule table (insert, update or delete) and like the other log tables (except_login_attempts_logs) they do not have a Foreign Key relation to the one it is logging to make sure any changes are recorded and not trigger a constrait. the Primary Keys have an AUTOINCREMENT attribute to also be used for the case of security investigations
CREATE TABLE "users_schedule_logs" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "action" TEXT NOT NULL CHECK("action" IN ('delete', 'update', 'insert')),
    "workdays" TEXT NOT NULL,
    "shift_start" NUMERIC NOT NULL DEFAULT '08:00:00' CHECK(shift_start GLOB '[0-2][0-9]:[0-5][0-9]:[0-5][0-9]'),
    "shift_end" NUMERIC NOT NULL DEFAULT '17:00:00' CHECK(shift_end GLOB '[0-2][0-9]:[0-5][0-9]:[0-5][0-9]'),
    "notes" TEXT NOT NULL DEFAULT "No notes were added.", -- tracks all notes if any
    "changed_by" TEXT NOT NULL,
    "timestamp" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- session logs. any updates, inserts, or deletes -- user forgot to logout, managers insert to logs to fix time session (timebased pay), and deletes if any.
CREATE TABLE "sessions_logs" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "employee_id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "action" TEXT NOT NULL CHECK("action" IN ('delete', 'update', 'insert')), -- always 'insert' action first then 'update' to log timeout and ip/loc then a 'delete' to prevent clouding the user_sessions table
    "session_in" NUMERIC NOT NULL,
    "session_out" NUMERIC NULL, 
    "country_in" TEXT, 
    "country_out" TEXT,
    "session_in_ip" TEXT NOT NULL,  
    "session_out_ip" TEXT NULL,
    "notes" TEXT NOT NULL DEFAULT "No notes were added.",
    "changed_by" TEXT NOT NULL, -- time in, time out
    "timestamp" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- logs blacklist statuses changes
CREATE TABLE "blacklist_logs" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "blacklist_id" INTEGER,
    "action" TEXT NOT NULL CHECK("action" IN ('delete', 'update', 'insert')),
    "ip_address" TEXT,
    "reason" TEXT NOT NULL DEFAULT "No notes were added.",
    "added_by" TEXT NOT NULL,
    "time_added" NUMERIC NOT NULL,
    "action_done_by" INTEGER NOT NULL,
    "timestamp" NUMERIC NOT NULL DEFAULT CURRENT_TIMESTAMP -- of trigger
);
-- ------------------------------------------------------------------
-- TRIGGERS
-- ---------------------------------------------------------------

-- -=accounts_logs TRIGGERS=- --
CREATE TRIGGER "users_insert_logs"
AFTER INSERT ON "users"
FOR EACH ROW
    BEGIN
        INSERT INTO "users_logs" ("user_id", "action", "personal_email", "password",  "account_creation", "verified_location", "account_status", "activation_token", "token_expiry", "role", "notes", "changed_by")
        VALUES (NEW."id", 'insert', NEW."personal_email", NEW."password", NEW."account_creation", NEW."verified_location", NEW."account_status",  NEW."activation_token", NEW."token_expiry", NEW."role", NEW."notes", NEW."changed_by");
    END;

CREATE TRIGGER "users_update_logs"
AFTER UPDATE ON "users"
FOR EACH ROW
    BEGIN
        INSERT INTO "users_logs" ("user_id", "action", "personal_email", "password",  "account_creation", "verified_location", "account_status", "activation_token", "token_expiry", "role", "notes", "changed_by")
        VALUES (NEW."id", 'update', NEW."personal_email", NEW."password", NEW."account_creation", NEW."verified_location", NEW."account_status", NEW."activation_token", NEW."token_expiry", NEW."role", NEW."notes", NEW."changed_by");
    END;

CREATE TRIGGER "users_delete_logs"
BEFORE DELETE ON "users"
FOR EACH ROW
    BEGIN
        INSERT INTO "users_logs" ("user_id", "action", "personal_email", "password",  "account_creation", "verified_location", "account_status", "activation_token", "token_expiry", "role", "notes", "changed_by")
        VALUES (OLD."id", 'delete', OLD."personal_email", OLD."password", OLD."account_creation", OLD."verified_location", OLD."account_status",  OLD."activation_token", OLD."token_expiry", OLD."role", OLD."notes", OLD."changed_by");
    END;

-- -=users_schedule_logs TRIGGERS=- --
CREATE TRIGGER "users_schedule_insert_logs"
AFTER INSERT ON "users_schedule"
FOR EACH ROW
    BEGIN
        INSERT INTO "users_schedule_logs" ("user_id", "action", "workdays", "shift_start", "shift_end", "notes", "changed_by")
        VALUES (NEW."user_id", 'insert', NEW."workdays", NEW."shift_start", NEW."shift_end", NEW."notes", NEW."changed_by");
    END;

CREATE TRIGGER "users_schedule_update_logs"
AFTER UPDATE ON "users_schedule"
FOR EACH ROW
    BEGIN
        INSERT INTO "users_schedule_logs" ("user_id", "action", "workdays", "shift_start", "shift_end", "notes", "changed_by")
        VALUES (NEW."user_id", 'update', NEW."workdays", NEW."shift_start", NEW."shift_end", NEW."notes", NEW."changed_by");
    END;

CREATE TRIGGER "users_schedule_delete_logs"
BEFORE DELETE ON "users_schedule"
FOR EACH ROW
    BEGIN
        INSERT INTO "users_schedule_logs" ("user_id", "action", "workdays", "shift_start", "shift_end", "notes", "changed_by")
        VALUES (OLD."user_id", 'delete', OLD."workdays", OLD."shift_start", OLD."shift_end", OLD."notes", OLD."changed_by");
    END;

-- -=sessions_logs TRIGGERS=- --
CREATE TRIGGER "sessions_insert_logs"
AFTER INSERT ON "user_sessions"
FOR EACH ROW
    BEGIN
        INSERT INTO "sessions_logs" ("user_id", "employee_id", "email", "action", "session_in", "session_out", "country_in", "country_out", "session_in_ip", "session_out_ip", "notes", "changed_by")
        VALUES (NEW."user_id", NEW."employee_id", NEW."email", 'insert', NEW."session_in", NEW."session_out", NEW."country_in", NEW."country_out", NEW."session_in_ip", NEW."session_out_ip", NEW."notes", NEW."changed_by");
    END;

CREATE TRIGGER "sessions_update_logs"
AFTER UPDATE ON "user_sessions"
FOR EACH ROW
    BEGIN
        INSERT INTO "sessions_logs" ("user_id", "employee_id", "email", "action", "session_in", "session_out", "country_in", "country_out", "session_in_ip", "session_out_ip", "notes", "changed_by")
        VALUES (NEW."user_id", NEW."employee_id", NEW."email", 'update', NEW."session_in", NEW."session_out", NEW."country_in", NEW."country_out", NEW."session_in_ip", NEW."session_out_ip", NEW."notes", NEW."changed_by");
    END;

CREATE TRIGGER "sessions_delete_logs"
BEFORE DELETE ON "user_sessions"
FOR EACH ROW
    BEGIN
        INSERT INTO "sessions_logs" ("user_id", "employee_id", "email", "action", "session_in", "session_out", "country_in", "country_out", "session_in_ip", "session_out_ip", "notes", "changed_by")
        VALUES (OLD."user_id", OLD."employee_id", OLD."email", 'delete', OLD."session_in", OLD."session_out", OLD."country_in", OLD."country_out", OLD."session_in_ip", OLD."session_out_ip", OLD."notes", OLD."changed_by");
    END;

-- -=blacklist_logs TRIGGERS=- --
CREATE TRIGGER "blacklist_insert_logs"
AFTER INSERT ON "blacklist"
FOR EACH ROW
    BEGIN
        INSERT INTO "blacklist_logs" ("blacklist_id", "action", "ip_address", "reason", "added_by", "time_added", "action_done_by")
        VALUES (NEW."id", 'insert', NEW."ip_address", NEW."reason", NEW."added_by", NEW."time_added", NEW."action_done_by");
    END;

CREATE TRIGGER "blacklist_update_logs"
AFTER INSERT ON "blacklist"
FOR EACH ROW
    BEGIN
        INSERT INTO "blacklist_logs" ("blacklist_id", "action", "ip_address", "reason", "added_by", "time_added", "action_done_by")
        VALUES (NEW."id", 'update', NEW."ip_address", NEW."reason", OLD."added_by", NEW."time_added", NEW."action_done_by");
    END;

CREATE TRIGGER "blacklist_delete_logs"
BEFORE DELETE ON "blacklist"
FOR EACH ROW
    BEGIN
        INSERT INTO "blacklist_logs" ("blacklist_id", "action", "ip_address", "reason", "added_by", "time_added", "action_done_by")
        VALUES (OLD."id", 'delete', OLD."ip_address", OLD."reason", OLD."added_by", OLD."time_added", OLD."action_done_by");
    END;