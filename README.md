# Intrusion and Activity Logger 
### Design Document

By Lara Jane Bugarin Sagun

Video overview: <URL HERE>

## Scope

Intrusion and Activity Logger or `ia_logger`, as a shorthand, is a python code that logs intrusion attacks or anomalies on a system, such as consecutive and or frequent failed login attempts, sudden change of geographic location, suspicious IP address usage, inconsistent time logins, and brute force login attempts all logged to a database. 

Other than logging intrusion attacks, ia_logger, have defensive measures built for the aforementioned attacks which includes bcrypt hashing, TOTP-based 2FA, geolocation/proxy detection, comprehensive audit logging using SQLite, and role-based access control. in addition to intrusion logs and defensive measures, it also logs user activities such as time-ins and outs logging, password and personal email changes, and paper trailing for all admin and system changes. It also can auto logout accounts that are past their scheduled time or are not logging out during breaks.

It's mimics a real system with login, logout, registration, activation, locking and unlocking, scheduling, termination, blacklisting and other subcommands for user and admin use capabilities that also have paper trailing and defensive measure capabilities to system attacks. 

Although ia_logger have such great capabilities it should be noted that it is independent to live data that any entities may have, to make it simple, the user activities such as say in a bank context will not record any auditing done by an employee on a consumer or client's bank account. it only logs employee activities but it does not include their interaction to consumer's database.

It is also should be noted that it does not touch much on HR field where there's a great possibility of mass registration of new employees, a batch setting of employee schedules, department divisions or even a separate database for applicant profiles to be transferred or absorbed to the database of this project. the scheduling does not include breaktime, lunch breaks, overtimes or a legally inconsistent employee schedule. 

The TOTP codes, 64-hexadecimal digits token and temporary passwords are flashed on the terminal than being sent to an email for demonstation but it is intended to be received on a secure medium.

a trusted network ranges was added to the database schema as most of business or organization entities use a private network which will be hard to demonstrate for this project 

## Functional Requirements

A user should be able to:

- Login to their account, in this setting a user logging in means timestamping the start of their session. the login process is theyre asked for their work email and password then will receive a totp. once authenticated only then their the timestamp is recorded in the database.
- Logout, means timestamping the end of their session. which will still need authentication process.
- Change their password which only works if they are logged in. In a case where they forgot their password, they will need to get it changed by an account with higher permission--an admin account.
- Activate their account. After being registered, the user need to activate their account where in they will need a temporary password and an activation token which will then theyre prompted to change their password if authenticated.
- Change their personal email which will receive any company related messages outside the workplace.

An admin, other than general rights listed above, should be able to:
- Register an account, where a work email will be generated using company domain and their first and lastname, generate temporary password for activation, employee id for logistics or other purpose it may serve, activation token which will be sent to their personal email or other secure medium they can access
- Lock an account, the system mostly does the locking but in any case where an account needs to be locked, an admin can do a so manually and leave a note for such event.
- Unlock an account, only and only if deemed so with documentation.
- Change location, accounts have verified location that are recorded during account activation which is being used to trigger any geographic location change anomaly. If an employee moves to a different country, say in a context where theyre moved to an international branch, this is the command to change the location to prevent the account from being tagged suspicious and not trigger a lock.
- Find user, a command for finding a user using their work email and get their `user_id`
- Generate a new temporary password, in any case a user does not remember or cannot find a copy of their temporary password for activation, this resets the temporary password and sends it to a secure medium the user can access
- Manual blacklisting, for IP addresses or personal emails 
- Terminate an account, a permanent account status that disables an account, in any case the user is re-employed a new account needs to be registered
- Set user schedule, a default work schedule is registered every account creation and this is a manual command to update or change the default schedule. It can set work days and time ranges for each work days
- Generate a new token, a manual generation of token which are used whenever an account is unlocked or during activation. Although the system generally does the generation of tokens, an admin can manually generate a token
- Fetch more information about a user which includes their employee ID, personal email, initialization of their account, the country they are based in, account status, totp key, hashed activation token, and token expiry  

Users cannot access admin only commands.
Admins need to login to be able to perform any admin only commands
Setting schedule does not set numbers of week ranges or bulk user scheduling nor have breaks, lunches, overtimes or inconsistent schedule capabilities but the project can certainly be developed to accomodate such change for more sophisticated systems.

## Representation

ia_logger includes a database with complete schema and data for testing, a sql file that includes the schema for review, and sample queries to be run on the database.

### Entities

Summary of the schema:

The schema have 8 major tables which are:
- **users** — A list of all users. contains every relevant user data, a user in this context is any employee. it stores all important data of a user including verified location for validating their login location, hashed password for authentication, totp validator code for totp authentication, hashed tokens for activation and account unlock authentication, IP addresses they used everytime they interact to the system, their location during login, account status and many more. A complete list of the columns will be listed later in this file.
- **users_schedule** — Holds the schedule for each employee, a time window where they are allowed to have access to the system, used for validating a user's time of access
- **user_sessions** — The table that records time ins and out, and user's IP address and location when doing so
- **login_attempts_logs** — Records all login attempts done, both success and fail with notes of what made the attempt fail 
- **security_events_logs** — Records all security events that caused an account to be locked
- **trusted_networks** — A list of IP ranges that are within the company or enterprise network, used for validating IP addresses
- **blacklist** — A list of blacklisted personal emails, and IP addresses. Where any detected credential stuffing IP addresses are recorded which will trigger a force logout to any successful login attempt used by the blacklisted IP address
- **used_totps** - A list of used OTPs to guard against reuse of tokens in the same time window 
- **log tables** (`users_logs`, `users_schedule_logs`, `sessions_logs`, `trusted_networks_logs`, `blacklist_logs`) — Maintain a full audit trail of all status and entity changes for accountability and moderation purposes. The logs tables are standalone with no enforced foreign key relationships back to their parent tables. Removing the foreign key constraints is intentional so that the deleted records can still be preserved in the audit trail.

The attributes each entities have:

- **users** — `id`, `email`, `employee_id`, `personal_email`, `password`, `account_creation`, `verified_location`, `country_location`, `ip_address`, `account_status`, `key_totp`, `activation_token`, `token_expiry`, `role`, `notes`, `changed_by`
- **users_schedule** — `id`, `user_id`, `workdays`, `shift_start`, `shift_end`, `notes`, `changed_by`
- **user_sessions** — `id`, `user_id`, `employee_id`, `email`, `session_in`, `session_out`, `session_in_ip`, `session_out_ip`, `notes`, `changed_by`
- **login_attempts_logs** — `id`, `user_id`, `email`, `ip_address`, `country`, `success`, `notes`, `timestamp`
- **security_events_logs** — `id`, `anomaly`, `user_id`, `malicious_ip`, `detected_location`, `notes`, `timestamp`
- **trusted_networks** — `id`, `label`, `ip_range`, `trust_level`, `added_by`, `time_added`, `is_active`
- **blacklist** — `id`, `personal_email`, `ip_address`, `reason`, `added_by`, `time_added`
- **used_totp** - `otp_code`, `user_id`, `time_added`
- **log tables** — Each log table stores a reference to its parent record, the action or status transition, and a timestamp.

### Relationships

The following entity-relationship diagram describes the structure of ia_logger:

![ERD](erd.png)

## Limitations

The database uses SQLite, which is not well-suited for high-concurrency production environments. It lacks built-in user authentication and row-level security, which means access control would need to be handled entirely at the application layer. 

