import argparse, bcrypt, getpass, hashlib, hmac, ipaddress, pyotp, random, re, requests, secrets, sqlite3, string
from validator_collection import checkers
from datetime import datetime, timezone, timedelta, time

# connection to sql file/database
DB_PATH = "./data/ia_logger.db"
DOMAIN_NAME = "company.com"
BLOCKED_STATUSES = {"locked", "flagged", "terminated"}
con = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
con.row_factory = sqlite3.Row
sqlite3.register_adapter(datetime, lambda d: d.isoformat())
# sqlite3.register_converter("NUMERIC", lambda s: time.fromisoformat(s.decode()))
sqlite3.register_converter("NUMERIC", lambda s: (
    datetime.fromisoformat(s.decode()) 
    if 'T' in s.decode() or ' ' in s.decode() 
    else time.fromisoformat(s.decode())
))

parser = argparse.ArgumentParser(description="[Intrusion and Activity Logger]")
subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

# general
subparsers.add_parser("activate", help="activate account")
subparsers.add_parser("login", help="login")
subparsers.add_parser("logout", help="logout")
subparsers.add_parser("change-password", help="change password")
subparsers.add_parser("update-email", help="update personal email")

# admin only
subparsers.add_parser("register", help="register/create an account.")
subparsers.add_parser("lock", help="manually lock an account")
subparsers.add_parser("unlock", help="unlocking or unflagging an account.")
subparsers.add_parser("change-location", help="change where user is based in/located.")
subparsers.add_parser("find-user", help="look for a user.")
subparsers.add_parser("edit-blacklist", help="add, remove or find from blacklist.")
subparsers.add_parser("terminate", help="terminate an account.")
subparsers.add_parser("set-schedule", help="set schedule.")
subparsers.add_parser("get-new-token", help="generate new token.")
subparsers.add_parser("get-info", help="more info on user's account.")

def is_valid_email(email):
    return checkers.is_email(email)

def is_valid_time(time):
    if not re.match(r"^[0-2][0-9]:[0-5][0-9]:[0-5][0-9]$", time):
        return False
    return True

def geolocation():
    response = requests.get("http://ip-api.com/json/?fields=query,country,status,proxy,hosting")
    return response.json()

def main():
    try:
        # run auto checks
        system_auto_logout()
        args = parser.parse_args()

# activates account
        if args.command == "activate":
            activate_account()
        elif args.command == "login":
            login()
        elif args.command == "logout":
            logout()
        elif args.command == "change-password":
            get_email = input("email: ").lower()
            fetch_user = find_user(get_email)
            if fetch_user is None:
                return None
            user_id = fetch_user["id"]
            update_password(user_id, get_email)
        elif args.command == "update-email":
            update_email()
# registers employee
        elif args.command == "register":
            admin = require_admin()
            if admin is None:
                return
            admin_id = admin["user_id"]
            admin_ip = admin["ip_address"]
            admin_loc = admin["country"]

            create_account(admin_ip, admin_loc, admin_id)
# locks an account
        elif args.command == "lock":
            admin = require_admin()
            if admin is None:
                return
            admin_id = admin["user_id"]
            admin_ip = admin["ip_address"]
            admin_loc = admin["country"]

            get_email = input("user's email: ").lower()
            fetch_user = find_user(get_email)
            if fetch_user is None:
                print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
                return
            user_id = fetch_user["id"]
            while True:
                notes = input("Reason: ")
                if notes != "":
                    confirm = input("Confirm? [y/N] ").lower()
                    if confirm == "y":
                        break
                    else:
                        return
            lock_account(user_id, notes, admin_ip, admin_loc, admin_id)
# unlocks or unflags an account
        elif args.command == "unlock":
            admin = require_admin()
            if admin is None:
                return
            admin_id = admin["user_id"]
            admin_ip = admin["ip_address"]
            admin_loc = admin["country"]

            unlock_account(admin_ip, admin_loc, admin_id)
# change location
        elif args.command == "change-location":
            admin = require_admin()
            if admin is None:
                return
            admin_id = admin["user_id"]
            admin_ip = admin["ip_address"]
            admin_loc = admin["country"]

            get_email = input("user's email: ").lower()
            fetch_user = find_user(get_email)
            if fetch_user is None:
                print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
                return
            user_id = fetch_user["id"]
            change_location(user_id, admin_ip, admin_loc, admin_id)
# find a user using their email
        elif args.command == "find-user":
            admin = require_admin()
            if admin is None:
                return
            get_email = input("user's email: ").lower()
            fetch_user = find_user(get_email)
            if fetch_user is None:
                print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
                return
            for key, value in dict(fetch_user).items():
                print(f"{key}: {value}")
# edit blacklist
        elif args.command == "edit-blacklist":
            admin = require_admin()
            if admin is None:
                return
            admin_id = admin["user_id"]
            ACTION = {"add", "remove", "find"}
            action = input("[add, remove. delete]\nAction: ").lower()
            if action in ACTION:
                while True:
                    ip_address = input("IP address: ")
                    if checkers.is_ip_address(ip_address):
                        notes = input("Reason: ")
                        if notes != "":
                            confirm = input("Confirm? [y/N] ").lower()
                            if confirm == "y":
                                break
                    else:
                        return
                edit_blacklist(action, ip_address, notes, admin_id)
            else:
                return
# terminate an account -- permanent / create a new account
        elif args.command == "terminate":
            admin = require_admin()
            if admin is None:
                return
            admin_id = admin["user_id"]
            if fetch_user is None:
                print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
                return
            user_id = fetch_user["id"]
            if user_id is None:
                    return
            while True:
                notes = input("Reason: ")
                if notes != "":
                    confirm = input("This cannot be undone.\nConfirm? [y/N] ").lower()
                    if confirm == "y":
                        break
                    else:
                        return
            terminate_account(user_id, notes, admin_id)
# change user's schedule ## no ip and loc tracking 
        elif args.command == "set-schedule":
            admin = require_admin()
            if admin is None:
                return
            admin_id = admin["user_id"]
            
            get_email = input("user's email: ").lower()
            fetch_user = find_user(get_email)
            if fetch_user is None:
                print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
                return
            user_id = fetch_user["id"]
            if user_id is None:
                return
            set_schedule(user_id, admin_id)
# request a new token
        elif args.command == "get-new-token":
            admin = require_admin()
            if admin is None:
                return
            admin_id = admin["user_id"]
            admin_ip = admin["ip_address"]
            admin_loc = admin["country"]
            
            get_email = input("user's email: ").lower()
            fetch_user = find_user(get_email)
            if fetch_user is None:
                print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
                return
            user_id = fetch_user["id"]
            while True:
                notes = input("Reason for token request: ")
                if notes != "":
                    confirm = input("Confirm? [y/N] ").lower()
                    if confirm == "y":
                        break
                    else:
                        return
            get_new_token(user_id, notes, admin_ip, admin_loc, admin_id)
# get more info about user using their email
        elif args.command == "get-info":
            admin = require_admin()
            if admin is None:
                return
            admin_id = admin["user_id"]

            get_email = input("user's email: ").lower()
            fetch_user = find_user(get_email)
            if fetch_user is None:
                print("The login information you entered is incorrect.  If you are having trouble please contact the admin or the customer service.")
                return
            user_id = fetch_user["id"]

            result = account_db(user_id)
            for key, value in dict(result).items():
                if (key == "activation_token") or (key == "key_totp"):
                    continue
                print(f"{key}: {value}")
        else:
            parser.print_help()
    except sqlite3.OperationalError:
        raise ("sqlite3.OperationalError: missing table")
    # # for NoneType error specifically
    except TypeError:
        raise ("TypeError")
    # # placeholder to keep try:
    except ValueError:
        return None

def is_strong_password(password):
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password): 
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def is_local_ip(ip_address):
    try:
        addr = ipaddress.ip_address(ip_address)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return True

# supposedly there's a list of trusted_network which is not possbile to add since i am using local ip and only fetching public ip, meaning no real list of ip ranges, it should go here as a check of valid ips. this only checks if it's proxy or hosting ip
def is_suspicious_ip(status, proxy, hosting):
    # malformed ip -- suspicious ip
    if status == "fail":
        return True
    # returns True or False
    return proxy or hosting

def is_unusual_time(user_id):
    cur = con.cursor()
    # fetch their schedule
    cur.execute(
        """
        SELECT "workdays", "shift_start", "shift_end" FROM "users_schedule"
        WHERE "user_id" = ?
        """,
        (user_id,)
    )
    row = cur.fetchone()

    if row is None:
        return True # if None, print user has no schedule ## how to make this not obvious
    
    workdays = row["workdays"]
    shift_start = row["shift_start"]
    shift_end = row["shift_end"]

    now = datetime.now(timezone.utc)
    today = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"][now.weekday()]

    if today in workdays:
        shift_start_dt = datetime.combine(now.date(), shift_start, tzinfo=timezone.utc)
        shift_end_dt   = datetime.combine(now.date(), shift_end, tzinfo=timezone.utc)

        # handles night shifter schedule
        if shift_end_dt < shift_start_dt:
            shift_end_dt += timedelta(days=1)

        if now < shift_start_dt - timedelta(minutes=30):
            return True   
        elif now > shift_end_dt + timedelta(minutes=30):
            return True
        else:
            return False
    else:
        return True
    
def check_credential_stuffing(ip_address):
    now = datetime.now(timezone.utc)
    window = now - timedelta(minutes=10)

    cur = con.cursor()
    cur.execute(
        """
        SELECT COUNT("ip_address") AS "count" FROM "login_attempts_logs"
        WHERE "ip_address" = ? AND "success" = ? AND "timestamp" BETWEEN ? AND ?
        """,
        (ip_address, 0, window, now)
    )
    same_ip = cur.fetchone()["count"]

    if same_ip >= 3:
        return True
    return False

# does not handle breaks, lunches, overtimes or legitimately inconsistent schedule
def set_schedule(user_id, changed_by):
    cur = con.cursor()
    cur.execute(
        """
        SELECT "user_id" FROM "users_schedule"
        WHERE "user_id" = ?
        """,
        (user_id,)
    )
    sched = cur.fetchone()
    while True:
        print("[MON, TUE, WED, THU, FRI, SAT, SUN]\nNOTE: Enter workdays separated by commas (e.g. MON,WED,FRI)")
        workdays = input("Workdays: ").upper()

        week_days = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
        work_days = workdays.replace(" ", "").split(",")
        if not all(day in week_days for day in work_days):
            print("Invalid. Try again.")
        if len(work_days) != len(set(work_days)):
            print("Invalid. Try again.")
        else:
            break

    while True:
        print("[HH:MM:SS]")
        shift_start = input("Shift start: ")
        shift_end = input("Shift end: ")
        if is_valid_time(shift_start) and is_valid_time(shift_end):
            confirm = input("Confirm? [y/N] ").lower()
            if confirm == "y":
                # Manual db insert new user without also inserting a schedule for the new user.
                if sched is None:
                    insert_schedule(user_id, workdays, shift_start, shift_end, "Schedule set by admin.", changed_by)
                    print("Successfully added a schedule.")
                    return
                else:
                    update_schedule(user_id, workdays, shift_start, shift_end, "Schedule updated by admin.", changed_by)
                    print("Successfully updated schedule.")
                    return
            else:
                print("Failed to make changes.")
                return
        else:
            print("Invalid time format. Use HH:MM:SS and try again.")

def update_schedule(user_id, workdays, shift_start, shift_end, notes, changed_by):
    cur = con.cursor()
    cur.execute(
        """
        UPDATE "users_schedule"
        SET "workdays" = ?, "shift_start" = ?, "shift_end" = ?, "notes" = ?, "changed_by" = ?
        WHERE "user_id" = ?
        """,
        (workdays, shift_start, shift_end, notes, changed_by, user_id)
    )
    con.commit()

def insert_schedule(user_id, workdays, shift_start, shift_end, notes, changed_by):
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO "users_schedule" (user_id, workdays, shift_start, shift_end, notes, changed_by)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, workdays, shift_start, shift_end, notes, changed_by)
    )
    con.commit()

# fetch list of blacklisted ips and emails from db
def fetch_blacklist():
    cur = con.cursor()
    cur.execute(
        """
        SELECT "ip_address", "time_added" FROM "blacklist"
        """
    )
    blacklist = cur.fetchall() # list of (user_id, ip_address) tuples
    if blacklist is None:
        return None
    return blacklist

def terminate_account(user_id, notes, terminated_by):
    cur = con.cursor()
    cur.execute(
        """
        UPDATE "users"
        SET "account_status" = ?, "notes" = ?, "changed_by" = ?
        WHERE "id" = ?
        """,
        ('terminated', notes, terminated_by, user_id)
    )
    con.commit()
    
def system_auto_logout():
    cur = con.cursor()
    # time in session exceeds end of shift
    cur.execute(
        """
        SELECT "user_id", "session_in", "session_in_ip" FROM "user_sessions"
        """
    )
    sessions = cur.fetchall()  # list of (user_id, ip_address) tuples
    now = datetime.now(timezone.utc) # datetime.utcnow()
    blacklisted = fetch_blacklist()

    # will cause lagging if there are many user logged in ## use daemon instead for or in any case this becomes somehting else other than a learning project
    for user_id, time_in, ip_address in sessions:

        blocked_ip = next((row for row in blacklisted if row[0] == ip_address), None)
        if blocked_ip:
            session_out_timestamp(user_id, ip_address, None, "System auto-logout. The ip_address is blacklisted.", "system-auto")
            security_logger("inconsistent_ip", user_id, ip_address, None, "Blacklisted IP detected.")
            flag_account(user_id, "Using a blacklisted ip_address.", None, None, "system-auto")
            continue  # move to next session, don't bother checking time

        if is_unusual_time(user_id):
            session_out_timestamp(user_id, ip_address, None, "System auto-logout. Past allowed time window.", "system-auto")
            security_logger("unusual_time", user_id, ip_address, None, "Account is past the allowed time window.")
            continue
        
        result = account_db(user_id)
        account_status = result["account_status"]
        if account_status == "flagged" or account_status == "locked":
            # recheck missed auto locks
            session_out_timestamp(user_id, ip_address, None, "System auto-logout. While logged in, the account is auto locked or flagged.", "system-auto")
            continue

        # all user's max hours per session is 4hrs 30mins (should time out for lunch break)
        time_in = time_in.replace(tzinfo=timezone.utc)
        if now > (time_in + timedelta(minutes=270)):
        # if (now - time_in) > timedelta(minutes=270):
            session_out_timestamp(user_id, ip_address, None, "System auto-logout. Max hour per session is 4hrs30mins.", "system-auto")
            security_logger("unusual_time", user_id, ip_address, None, "Account active for more than 4hrs30mins.")

# insert into blacklist table and lock an account
def edit_blacklist(action, ip_address, notes, admin_id):
    cur = con.cursor()
    if action == "add":
        cur.execute(
            """
            INSERT INTO "blacklist" (ip_address, reason, added_by)
            VALUES (?, ?, ?)
            """,
            (ip_address, notes, admin_id)
        )
        con.commit()
        print(f"{ip_address} added to blacklist.")
        return
    
    elif action == "remove":
        cur.execute(
            """ 
            UPDATE "blacklist"
            SET "reason = ?", "action_done_by" = ?
            WHERE "ip_address" = ?
            """,
            (notes, admin_id, ip_address)
        )
        con.commit()

        cur.execute(
            """
            DELETE FROM "blacklist"
            WHERE "ip_address" = ?
            """,
            (ip_address,)
        )
        con.commit()
        print(f"{ip_address} removed from blacklist.")
        return
    elif action == "find":
        cur.execute(
            """ 
            SELECT "ip_address" FROM "blacklist"
            WHERE "ip_address" = ?   
            """,
            (ip_address,)
        )
        if cur.fetchone() is None:
            return None
        else:
            return cur.fetchone()

def get_schedule(user_id):
    cur = con.cursor()
    cur.execute(
        """
        SELECT "workdays", "shift_start", "shift_end" FROM "users_schedule"
        WHERE "user_id" = ?
        """,
        (user_id,)
    )
    row = cur.fetchone()
    if row is None:
        return None
    return row
    
# employee_id for assigning company owned materials for logistics (e.g. laptops, headphones, etc)    
def generate_employee_id():
    while True:
        generate = random.randint(10000000, 99999999)
        gen = str(generate)
        if not any(gen.count(digit) >= 3 for digit in set(gen)):
            cur = con.cursor()
            cur.execute(
                """
                SELECT "employee_id" FROM "users" WHERE "employee_id" = ?
                """,
                (gen,)
            )
            if cur.fetchone() is None:
                return gen
        
# all email should be using company domain, all personal email are for employee notice (e.g. hr/on-boarding updates, company events etc.)
def generate_email():
    first_name = input("First name: ").strip()
    last_name = input("Last name: ").strip()
    fullname = last_name + first_name
    # domain_name = "company.com"
    email = fullname.lower() + '@' + DOMAIN_NAME

    cur = con.cursor()
    cur.execute(
        """
        SELECT COUNT("email") FROM "users"
        WHERE "email" LIKE ?
        """,
        (fullname.lower() + '%@' + DOMAIN_NAME,)
    )
    count = cur.fetchone()[0]

    if count > 0:
        email = fullname + str(count) + '@' + DOMAIN_NAME

    return email

# dictionary tracker. record that an admin created the account
def create_account(admin_ip, admin_loc, registered_by):
    print("[Create account]")

    # generate work email for the user
    email = generate_email()
    print("User's work email: ", email)

    #generate employee id for logistics
    employee_id = generate_employee_id()
    print("User's employee id: ", employee_id)

    # will be salted
    activation_token = secrets.token_hex(32)
    print("Activation code:", activation_token)

    while True:
        get_user_email = input("User's personal email: ")
        if is_valid_email(get_user_email) and validate_personal_email(get_user_email):
            break
        else:
            print("Invalid email.")

    key_totp = pyotp.random_base32()
    
    token_db = hashlib.sha256(activation_token.encode()).hexdigest()

    token_expiry = datetime.now(timezone.utc) + timedelta(hours=24)
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO "users" (email, personal_email, password, employee_id, account_status, key_totp, activation_token, token_expiry, role, notes, changed_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (email, get_user_email, None, employee_id, 'inactive', key_totp, token_db, token_expiry, 'user', f"Account created.\nAdmin_ip:{admin_ip} Admin_loc:{admin_loc}", registered_by)
    )
    con.commit()

    fetch_user = find_user(email)
    if fetch_user is None:
        print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
        return
    user_id = fetch_user["id"]
    insert_schedule(user_id, "MON,TUE,WED,THU,FRI", "00:00:00", "08:00:00", "Default schedule set during registration.", registered_by)
    print("Successfully registered an account.")
    return

# checks the user db if it's already being used by other user // should be unique otherwise an error will occur in sqlite querying
def validate_personal_email(personal_email):
    cur = con.cursor()
    cur.execute(
        """
        SELECT "personal_email" FROM "users"
        WHERE "personal_email" = ?
        """,
        (personal_email,)
    )
    # if it doesnt exist
    if (cur.fetchone()) is None:
        return True
    return False

def get_credentials(email):
    cur = con.cursor()
    cur.execute(
        """
        SELECT "id", "email", "password" FROM "users"
        WHERE "email" = ?
        """,
        (email,)
    )
    row = cur.fetchone() 

    if row is None:
        return (None, None, None)
    return row

def find_user(email):
    cur = con.cursor()
    cur.execute(
        """
        SELECT "id", "role" FROM "users"
        WHERE "email" = ?
        """,
        (email,)
    )
    row = cur.fetchone() 
    if row is None:
        return None
    return row

def status_checker(user_id):
    result = account_db(user_id)
    account_status = result["account_status"]
    if account_status == "inactive":
        return ("inactive")
    elif account_status == "active":
        return ("active")
    elif account_status == "locked":
        return ("locked")
    elif account_status == "unlocked":
        return ("unlocked")
    elif account_status == "flagged":
        return ("flagged")
    
def change_location(user_id, admin_ip, admin_loc, changed_by):
    if user_id is None:
            print("The information you provided is incorrect.")
            return 

    new_location = input("user's new country location: ").capitalize()
    while True:
        notes = input("Reason for location change: ")
        if notes != "":
            confirm = input("Confirm? [y/N]" ).lower()
            if confirm == "y":
                break
            else:
                print("No changes were made.")
                return
    cur = con.cursor()
    cur.execute(
        """
        UPDATE "users"
        SET "verified_location" = ?, "notes" = ?, "changed_by" = ?
        WHERE "id" = ?
        """,
        (new_location, f"Reason:{notes}.\nAdmin_ip:{admin_ip} Admin_loc:{admin_loc}", changed_by, user_id)
    )
    con.commit()
    print("Successfully updated verified location.")
    return

# flags: two lockouts, blacklisted--
def login():
    tracker = geolocation()
    ip_address = tracker["query"]
    country = tracker["country"]
    status = tracker["status"]
    proxy = tracker["proxy"]
    hosting = tracker["hosting"]

    now = datetime.now(timezone.utc)
    weeks_old = now - timedelta(days=7)

    print("[Log in]")
    get_email = input("email: ").lower()
    
    fetch_user = find_user(get_email)
    if fetch_user is None:
        print("The login information you entered is incorrect. If you are having trouble logging in please contact the admin or the customer service.")
        return
    user_id = fetch_user["id"]
    
    result = account_db(user_id)
    employee_id = result["employee_id"]
    verified_location = result["verified_location"]
    account_status = result["account_status"]

    # check account status
    if account_status in BLOCKED_STATUSES:
        print("Sytem error. Please try again or contact the admin.")
        return
    
    elif (account_status == "inactive") or (verified_location is None):
        print("The account you are trying to access is not activated.")
        return
    
    # if already logged in
    if check_session_db(user_id):
        return
    
    if is_local_ip(ip_address):
        login_fail_logger(user_id, get_email, ip_address, country, 0, "Detected a local IP address.")
        security_logger("inconsistent_ip", user_id, ip_address, country, "Credential stuffing detected.")
        print("Sytem error. Please try again or contact the admin.")
        return
    
    if check_credential_stuffing(ip_address):
        login_fail_logger(user_id, get_email, ip_address, country, 0, "Detected a credential stuffing.")
        edit_blacklist("add", ip_address, "Credential stuffing detected.", "system-auto")
        security_logger("credential_stuffing", user_id, ip_address, country, "Credential stuffing detected.")
        system_auto_logout()
        print("System error. Please try again or contact the admin.")
        return
    
    if is_suspicious_ip(status, proxy, hosting):
        login_fail_logger(user_id, get_email, ip_address, country, 0, "Detected a suspicious IP address.")
        security_logger("inconsistent_ip", user_id, ip_address, country, "Detected a proxy or hosting ip address")
        lock_account(user_id, "Detected a suspicious ip address. System auto-lock initiated.", None, None, "system-auto")
        # IP anomalies can trigger locking, so it can also trigger a flagging
        attempts_week = failed_login_count(user_id, weeks_old, now)
        if attempts_week >= 6:
            flag_account(user_id, "Reached maximum attempts in a week. System auto-flag initiated.", None, None, "system-auto")
        print("System error. Please try again or contact the admin.")
        return

    if verified_location != country:
        login_fail_logger(user_id, get_email, ip_address, country, "Detected a location change.")
        security_logger("new_country_login", user_id, ip_address, country, "Trying to login from a different country.") 
        print("System error. Please try again or contact the admin.")
        return
    
    if is_unusual_time(user_id):
        login_fail_logger(user_id, get_email, ip_address, country, 0, "Not allowed time window for login.")
        security_logger("unusual_time", user_id, ip_address, country, "Trying to login out of time schedule.")
        print("System error. Please try again or contact the admin.")
        return
    
    
    if account_status == "unlocked":
        # print("[For demo purpose.]\nYour activation code:", activation_token)
        verified_token = verify_token(user_id, get_email, ip_address, country)
        if verified_token is None:
            print("Login cancelled.")  
            return
        elif verified_token:
            print("To secure your account please set up a new password.")
            change_password(user_id, get_email, "active", "update password after account unlock and change account_status from 'unlocked' to 'active'")
            session_in_timestamp(user_id, employee_id, get_email, ip_address, country, "Time-in.")
            login_fail_logger(user_id, get_email, ip_address, country, 1, "Login successful.")
                     
        else:
            print("System error. Please try again or contact the admin.")
            return

    # validate password
    elif account_status == "active":
        verified_password = verify_password(user_id, get_email, ip_address, country)
        if verified_password is None:
            print("Login cancelled.")  
            return
        elif verified_password:
            session_in_timestamp(user_id, employee_id, get_email, ip_address, country, "Time-in.")
            login_fail_logger(user_id, get_email, ip_address, country, 1, "Login successful.")

    else:
        print("System error. Please try again or contact the admin.")
        return
    
    print("Login successful.")

# fetch session activity
def check_session_db(user_id):
    cur = con.cursor()
    cur.execute(
        """
        SELECT "session_in" FROM "user_sessions"
        WHERE "user_id" = ?
        ORDER BY "session_in" DESC
        LIMIT 1
        """,
        (user_id,)
    )
    row = cur.fetchone()
    if row is None:
        return False
    elif row["session_in"] is not None:
        return True
    return False

# fetch other user info other than basic creds
def account_db(user_id):
    cur = con.cursor()
    cur.execute(
        """
        SELECT "employee_id", "personal_email", "account_creation", "verified_location", "account_status", "key_totp", "activation_token", "token_expiry" FROM "users"
        WHERE "id" = ?
        """,
        (user_id,)
    )
    row = cur.fetchone()

    if row is None:
        return None
    return row


# failed attempts logger
def login_fail_logger(user_id, email, ip_address, country, success, notes):
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO "login_attempts_logs" (user_id, email, ip_address, country, success, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, email, ip_address, country, success, notes)
    )
    con.commit()    

# reimplement
def activation_fail_logger(user_id, email, ip_address, country):
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO "activation_attempts_logs" (user_id, email, ip_address, country, success)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, email, ip_address, country, 0)
    )
    con.commit()

def register_fail_logger(email, ip_address, country):
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO "register_attempts_logs" (email, ip_address, country)
        VALUES (?, ?, ?)
        """,
        (email, ip_address, country)
    )
    con.commit()
# reimplement

# for anomaly detection lock account
def lock_account(user_id, notes, admin_ip, admin_loc, locked_by):
    cur = con.cursor()
    cur.execute(
        """
        UPDATE "users" 
        SET "account_status" = ?, "notes" = ?, "changed_by" = ?
        WHERE "id" = ?
        """,
        ('locked', f"Reason:{notes}.\nAdmin_ip:{admin_ip} Admin_loc:{admin_loc}", locked_by, user_id)
    )
    con.commit()

# not called
# for repeated anomaly detection
def flag_account(user_id, notes, admin_ip, admin_loc, flagged_by):
    cur = con.cursor()
    cur.execute(
        """
        UPDATE "users" 
        SET "account_status" = ?, "notes" = ?, "changed_by" = ?
        WHERE "id" = ?
        """,
        ('flagged', f"Reason:{notes}.\nAdmin_ip:{admin_ip} Admin_loc:{admin_loc}", flagged_by, user_id)
    )
    con.commit()

# manual force logout
def admin_logout(notes, changed_by):
    tracker = geolocation()
    ip_address = tracker["query"]
    country = tracker["country"]

    get_email = input("email: ").lower()
    fetch_user = find_user(get_email)
    if fetch_user is None:
        print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
        return
    user_id = fetch_user["id"]

    session_out_timestamp(user_id, ip_address, country, notes, changed_by)

# activation shouldnt log a user as suspicious if they were just trying to activate their account and it not their schedule to work.
def activate_account():
    tracker = geolocation()
    ip_address = tracker["query"]
    country = tracker["country"]
    status = tracker["status"]
    proxy = tracker["proxy"]
    hosting = tracker["hosting"]

    print("[Activate Account]")
    get_email = input("email: ").lower()
    
    # validate user exists
    fetch_user = find_user(get_email)
    if fetch_user is None:
        print("The login information you entered is incorrect. If you are having trouble activating your account please contact the admin or the customer service.")
        return
    user_id = fetch_user["id"]
    # check account status
    result = account_db(user_id)
    #  account_creation = result["account_creation"]
    account_status = result["account_status"]
    if account_status in BLOCKED_STATUSES:
        print("The login information you entered is incorrect. If you are having trouble activating your account please contact the admin or the customer service.")
        # add list of error codes??? or nah???
        return

    # if ever been activated there's no need to be here activating an account.
    elif activated(user_id):
        print("Proceed to login.")

    # normal intrusion checks
    if is_local_ip(ip_address):
        print("Sytem error. Please try again or contact the admin.")
        return
    
    if check_credential_stuffing(ip_address):
        edit_blacklist("add", None, ip_address, "Credential stuffing detected.", "system-auto")
        security_logger("credential_stuffing", user_id, ip_address, country, "Credential stuffing detected.")
        print("System error. Please try again or contact the admin.")
        return
    
    if is_suspicious_ip(status, proxy, hosting):
        security_logger("inconsistent_ip", user_id, ip_address, country, "Detected a proxy or hosting ip address")
        lock_account(user_id, "Detected a suspicious ip address. System auto-lock initiated.", None, None, "system-auto")
        print("System error. Please try again or contact the admin.")
        return
    
    now = datetime.now(timezone.utc)
    token_expiry_db = result["token_expiry"]
    token_expiry = token_expiry_db.replace(tzinfo=timezone.utc)

    if account_status == "inactive":
        if token_expiry > now:
            lock_account(user_id, "Expired credentials.", None, None, "system-auto")
            print("Sytem error. Please try again or contact the admin.")
            return

        elif token_expiry < now:
            if verify_token(user_id, get_email, ip_address, country):
                print("Setup a new password")
                change_password(user_id, get_email, account_status, "updated password during activation.")
            else:    
                return
    
    if (account_status == "unlocked") and (not activated(user_id)):
        if token_expiry < now:
            lock_account(user_id, "Unresponsive account.", None, None, "system-auto")
            print("Sytem error. Please try again or contact the admin.")
            return

        elif token_expiry > now:
            if verify_token(user_id, get_email, ip_address, country):
                print("Setup a new password")
                change_password(user_id, get_email, account_status, "update password during activation.")
            else:
                return
        else:
            return

    # add verified_location of the user when they activated which will be use to validate their location all throughout account existence unless ofc updated by admin otherwise will not be able to login
    cur = con.cursor()
    cur.execute(
        """
        UPDATE "users"
        SET "verified_location" = ?, "account_status" = ?, "notes" = ?, "changed_by" = ?
        WHERE "id" = ?
        """,
        (country, 'active', 'Account activated and verified location.', user_id, user_id)
    )
    con.commit()
    
    print("Successfully updated password.")
    print("Proceed to login.")

def activated(user_id):
    cur = con.cursor()
    cur.execute(
        """
        SELECT "account_status" FROM "users_logs"
        WHERE "user_id" = ? AND "account_status" = ?
        LIMIT ?
        """,
        (user_id, 'active', 1)
    )
    row = cur.fetchall()
    if "active" in row:
        return True
    return False
            
def session_in_timestamp(user_id, employee_id, email, ip_address, country, notes):
        cur = con.cursor()
        cur.execute(
            """
            INSERT INTO "user_sessions" (user_id, employee_id, email, country_in, session_in_ip, notes, changed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, employee_id, email, country, ip_address, notes, user_id)
        )
        con.commit()

def session_out_timestamp(user_id, ip_address, country, notes, changed_by):
    session_out = datetime.now(timezone.utc)
    # log their session out, their location and additional data before deleting it not cloud the table
    if check_session_db(user_id):
        cur = con.cursor()
        cur.execute(
            """
            UPDATE "user_sessions" 
            SET "session_out" = ?, "country_out" = ?, "session_out_ip" = ?, "notes" = ?, "changed_by" = ?
            WHERE "user_id" = ?
            """,
            (session_out, country, ip_address, notes, changed_by, user_id)
        )
        con.commit()

        # delete record to not cloud user_sessions
        cur.execute(
            """
            DELETE FROM "user_sessions"
            WHERE "user_id" = ?
            """,
            (user_id,)
        )
        con.commit()
    
def logout():
    tracker = geolocation()
    ip_address = tracker["query"]
    country = tracker["country"]
    status = tracker["status"]
    proxy = tracker["proxy"]
    hosting = tracker["hosting"]

    print("[Log out]")

    get_email = input("email: ").lower()
    fetch_user = find_user(get_email)
    if fetch_user is None:
        return None
    user_id = fetch_user["id"]

    result = account_db(user_id)
    account_status = result["account_status"]
    verified_location = result["verified_location"]
    if account_status in BLOCKED_STATUSES:
        print("The system can't access your account. Please contact the admin.")
        return

    session_in = check_session_db(user_id)
    if not session_in:
        print("Please login.")
        return

    if is_local_ip(ip_address):
        security_logger("inconsistent_ip", user_id, ip_address, country, "Detected a proxy or hosting ip address")
        print("Sytem error. Please try again or contact the admin.")
        return
    
    if check_credential_stuffing(ip_address):
        edit_blacklist("add", None, ip_address, "Credential stuffing detected.", "system-auto")
        security_logger("credential_stuffing", user_id, ip_address, country, "Credential stuffing detected.")
        print("System error. Please try again or contact the admin.")
        return

    if is_suspicious_ip(status, proxy, hosting):
        security_logger("inconsistent_ip", user_id, ip_address, country, "Detected a proxy or hosting ip address")
        print("System error. Please try again or contact the admin.")
        return

    if verified_location != country:
        security_logger("new_country_login", user_id, ip_address, country, "Trying to login from a different country.") 
        print("System error. Please try again or contact the admin.")
        return

    verified_password = verify_password(user_id, get_email, ip_address, country)
    if verified_password is None:
        print("Logout cancelled.")
        return
    elif verified_password is False:
        print("The information you provided is incorrect.")
        return   
    elif verified_password and session_in:
        log_out = input("Proceed to logout? [y/N] ").lower()
        if log_out == "y":
            print("Logout successful")
            session_out_timestamp(user_id, ip_address, country, "time-out", user_id)
            return
        else:
            print("Failed to logout.")
            return
    else:
        return ("Something went wrong.")

def unlock_account(admin_ip, admin_loc, admin_id):
    print("[Enter work email of the locked out user.]")
    get_email = input("User's email: ").lower()
    fetch_user = find_user(get_email)
    if fetch_user is None:
        print("The information you provided is incorrect.")
        return None
    user_id = fetch_user["id"]
    result = account_db(user_id)
    account_status = result["account_status"]
    token_expiry_db = result["token_expiry"]
    token_expiry = token_expiry_db.replace(tzinfo=timezone.utc)

    recents = attempts_logs_recent(user_id)
    recents_more = attempts_logs_older(user_id)
    now = datetime.now(timezone.utc)
    
    print("---recents---")
    for row in recents:
        for key, value in dict(row).items():
            print(f"{key}: {value}")
        print("---")
    print('[Type "more" to see older records on the Reason field]')
    print('[To cancel, leave the Reason field empty and press Enter]')
    while True:
        notes = input("Reason for unlock: ").lower()
        if notes == "more":
            print("---")
            if recents_more is None:
                print("No older records found.")
            for row in recents_more:
                for key, value in dict(row).items():
                    print(f"{key}: {value}")
                print("---more---")
        elif notes != "":
            confirm = input("This cannot be undone.\nConfirm unlock? [y/N] ").lower()
            if confirm == "y":
                break
            else:
                print("Account unlock cancelled.")
                return
        elif notes == "":
            print("Account unlock cancelled.")
            return

    if account_status == "locked" or account_status == "flagged":

        # locked accounts that were never activated and have expired credentials.
        if (not activated(user_id)) and (now > token_expiry): 
            get_new_token(user_id, "Locked unactivated account. Expired credentials. Generated new token.", admin_ip, admin_loc, admin_id)
            unlock_reset(user_id, notes, admin_ip, admin_loc, admin_id)
            print("Successfully unlocked.")
            return
        # locked accounts that were never activated with active credentials.
        elif(not activated(user_id)) and (now < token_expiry):
            unlock_reset(user_id, notes, admin_ip, admin_loc, admin_id)
            print("Successfully unlocked.")
            return
        # locked accounts that were activated.
        if account_status == "locked" :
            # for login
            get_new_token(user_id, "Locked active account. Expired credentials. Generated new token.", admin_ip, admin_loc, admin_id)
            unlock_reset(user_id, notes, admin_ip, admin_loc, admin_id)
            print("Successfully unlocked.")
            return
        elif account_status == "flagged":
            print("The account you are trying to unlock is flagged. Make sure it has proper documentation and was thoroughly investigated before unlocking.")          
            get_new_token(user_id, "Auto-generated token for unlocking a flagged account.", admin_ip, admin_loc, admin_id)
            unlock_reset(user_id, notes, admin_ip, admin_loc, admin_id)
            print("Successfully unlocked.")
            return
        else:
            return
    
    elif account_status == "terminated":
        print("System error. Please try again or contact the admin.")
        return
    else:
        print("Proceed to login.") 
        return

# next time use fetch/update/insert/delete for function naming 
def fetch_used_otp(user_id, otp_code):
    cur = con.cursor()
    cur.execute(
        """
        SELECT "otp_code", "time_added" FROM "used_totps"
        WHERE "user_id" = ? AND "otp_code" = ?
        """,
        (user_id, otp_code)
    )
    row = cur.fetchone()
    if row is None:
        return None
    return row 

def insert_used_otp(otp_code, user_id):
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO "used_totps" (otp_code, user_id)
        VALUES (?, ?)
        """,
        (otp_code, user_id)
    )
    con.commit()

def verify_old_password(email):
    fetch_credentials = get_credentials(email)
    password_db = fetch_credentials["password"]
    tries = 5
    while tries > 0:
        get_current_password = getpass.getpass("current password: ")
        
        bcrypt_get_cur_pw = get_current_password.encode()
        bcrypt_pw_db = password_db.encode()

        if bcrypt.checkpw(bcrypt_get_cur_pw, bcrypt_pw_db):
            return True
        elif get_current_password == "":
            return None
        else:
            tries -= 1
            if tries == 0:
                return False
    
def verify_otp(user_id, email, ip_address, country):
    cur = con.cursor()
    print("To cancel do not put anything and press Enter")
    result = account_db(user_id)
    key_totp = result["key_totp"]

    now = datetime.now(timezone.utc)
    weeks_old = now - timedelta(days=7)
    day_old = now - timedelta(hours=24)
    cutoff = now - timedelta(minutes=1)

    cur.execute(
        """
        DELETE FROM "used_totps"
        WHERE "user_id" = ? AND "time_added" < ?
        """,
        (user_id, cutoff)
    )
    con.commit()    
    
    totp_code = pyotp.TOTP(key_totp)

    totp_tries = 3
    while totp_tries > 0:
        # send totp / flash for demo
        print("[For demo purpose.]\nConfirm your login with the code", totp_code.now())
        get_totp = input("2FA: ")
        # clock drift
        if get_totp == "":
            return None
        if totp_code.verify(get_totp, valid_window=1):
            used_totp = fetch_used_otp(user_id, get_totp)
            # if verified and doesnt exist in the used_totp table
            if used_totp is None:
                # insert to the table the otp used and let them through
                insert_used_otp(get_totp, user_id)
                return True
            
            # if verified but exist in the used_totp table
            elif used_totp is not None:
                print("Failed. The code either expired or incorrect. Please try again.")
                login_fail_logger(user_id, email, ip_address, country, 0, "Trying to reuse an OTP code that was recently added to used OTPs.")
                return False
            else:
                print("Something went wrong.")
                return False

        else:
            totp_tries -= 1
            print("Failed. The code either expired or incorrect. Please try again.")
            login_fail_logger(user_id, email, ip_address, country, 0, "Failed OTP verification.")
            attempts_day = failed_login_count(user_id, day_old, now)
            attempts_week = failed_login_count(user_id, weeks_old, now)
            if attempts_day >= 3:
                notes = "Reached maximum attempts in a day. System auto-lock initiated."
                lock_account(user_id, notes, None, None, "system-auto")
                security_logger("too_many_failed_attempts", user_id, ip_address, country, notes)
                return False
            elif attempts_week >= 6:
                notes = "Reached maximum attempts in a week. System auto-flag initiated."
                flag_account(user_id, notes, None, None, "system-auto")
                security_logger("too_many_failed_attempts", user_id, ip_address, country, notes)
                return False
            if totp_tries == 0:
                notes = "Failed otp verification. System auto-lock initiated."
                lock_account(user_id, notes, None, None, "system-auto")
                security_logger("too_many_failed_attempts", user_id, ip_address, country, notes)
                print("Too many invalid attempts. Please contact the admin.")
                return False
            
def verify_password(user_id, email, ip_address, country):
    fetch_credentials = get_credentials(email)
    password_db = fetch_credentials["password"]
    
    now = datetime.now(timezone.utc)
    weeks_old = now - timedelta(days=7)
    day_old = now - timedelta(hours=24)

    tries = 3
    while tries > 0:
        print("To cancel do not put anything and press Enter")
        get_password = getpass.getpass("password: ")
        bcrypt_get_pw = get_password.encode("utf-8")
        bcrypt_pw_db = password_db.encode("utf-8")
                
        # password is correct
        if bcrypt.checkpw(bcrypt_get_pw, bcrypt_pw_db):
            verified_otp = verify_otp(user_id, email, ip_address, country)
            if verified_otp is None or verified_otp == "":
                return None
            elif verified_otp:
                return True
            else:
                return False
            
        elif get_password == "":
            return None
        
        # password is incorrect
        else:
            tries -= 1
            print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
            login_fail_logger(user_id, email, ip_address, country, 0, "Failed password verification.")
            attempts_day = failed_login_count(user_id, day_old, now)
            attempts_week = failed_login_count(user_id, weeks_old, now)
            if attempts_day >= 3:
                notes = "Reached maximum attempts in a day. System auto-lock initiated."
                lock_account(user_id, notes, None, None, "system-auto")
                security_logger("too_many_failed_attempts", user_id, ip_address, country, notes)
                return False
            elif attempts_week >= 6:
                notes = "Reached maximum attempts in a week. System auto-flag initiated."
                flag_account(user_id, notes, None, None, "system-auto")
                security_logger("too_many_failed_attempts", user_id, ip_address, country, notes)
                return False
            if tries == 0:
                notes = "Reached maximum login attempts. System auto-lock initiated."
                lock_account(user_id, notes, None, None, "system-auto")
                security_logger("too_many_failed_attempts", user_id, ip_address, country, notes)
                print("Too many invalid attempts. Please contact the admin.")
                return False

def verify_token(user_id, email, ip_address, country):
    result = account_db(user_id)
    token_db = result["activation_token"]
    token_expiry = result["token_expiry"]

    now = datetime.now(timezone.utc)
    weeks_old = now - timedelta(days=7)
    day_old = now - timedelta(hours=24)
    
    token_tries = 3
    while token_tries > 0:
        print("To cancel do not put anything and press Enter")
        get_token = input("Enter activation code: ")
        if get_token == "":
            return None

        hash_token = hashlib.sha256(get_token.encode()).hexdigest()

        if hmac.compare_digest(hash_token, token_db) and (now < token_expiry):
            cur = con.cursor()
            cur.execute(
                """
                UPDATE "users" 
                SET "activation_token" = ?, "token_expiry" = ?, "notes" = ?
                WHERE "id" = ?
                """,
                (None, None, 'cleared token', user_id)
            )
            con.commit()
            return True
        
        elif hmac.compare_digest(hash_token, token_db) and (now > token_expiry):
            print("The token you entered is expired. A new token have been sent to your account, please try again.")
            get_new_token(user_id, "Auto reset token by system's token verification check.", None, None, "system-auto")
            return False
        
        else:
            token_tries -= 1
            print("Invalid token.")
            login_fail_logger(user_id, email, ip_address, country, 0, "Failed token verification.")
            attempts_day = failed_login_count(user_id, day_old, now)
            attempts_week = failed_login_count(user_id, weeks_old, now)
            if attempts_day >= 3:
                notes = "Reached maximum attempts in a day. System auto-lock initiated."
                lock_account(user_id, notes, None, None, "system-auto")
                security_logger("too_many_failed_attempts", user_id, ip_address, country, notes)
                return False
            elif attempts_week >= 6:
                notes = "Reached maximum attempts in a week. System auto-flag initiated."
                flag_account(user_id, notes, None, None, "system-auto")
                security_logger("too_many_failed_attempts", user_id, ip_address, country, notes)
                return False
            if token_tries == 0:
                notes = "Reached maximum token verification attempts. System auto-lock initiated."
                lock_account(user_id, notes, None, None, "system-auto")
                security_logger("too_many_failed_attempts", user_id, ip_address, country, notes)
                print("Too many invalid attempts. Please contact the admin.")
                return False

def update_email():
    tracker = geolocation()
    ip_address = tracker["query"]
    country = tracker["country"]
    status = tracker["status"]
    proxy = tracker["proxy"]
    hosting = tracker["hosting"]

    get_email = input("work email: ").lower()
    fetch_user = find_user(get_email)
    if fetch_user is None:
        return None
    user_id = fetch_user["id"]
    session_in = check_session_db(user_id)
    result = account_db(user_id)
    personal_email = result["personal_email"]
    account_status = result["account_status"]
    verified_location = result["verified_location"]

    if user_id is None:
        print("User not found.")
        return
    
    if account_status in BLOCKED_STATUSES:
        print("Sytem error. Please try again or contact the admin.")
        return

    if not session_in:
        print("Please log in.")
        return
    
    if is_local_ip(ip_address):
        security_logger("inconsistent_ip", user_id, ip_address, country, "Detected a proxy or hosting ip address")
        print("Sytem error. Please try again or contact the admin.")
        return
    
    if check_credential_stuffing(ip_address):
        edit_blacklist("add", None, ip_address, "Credential stuffing detected.", "system-auto")
        security_logger("credential_stuffing", user_id, ip_address, country, "Credential stuffing detected.")
        print("System error. Please try again or contact the admin.")
        return

    if is_suspicious_ip(status, proxy, hosting):
        security_logger("inconsistent_ip", user_id, ip_address, country, "Detected a proxy or hosting ip address")
        print("System error. Please try again or contact the admin.")
        return

    if verified_location != country:
        security_logger("new_country_login", user_id, ip_address, country, "Trying to login from a different country.") 
        print("System error. Please try again or contact the admin.")
        return

    elif session_in:
        verified_password = verify_password(user_id, get_email, ip_address, country)
        if verified_password:
            print("registered personal email:", personal_email)
            while True:
                new_email = input("new email: ")
                if (not is_valid_email(new_email)) or (not validate_personal_email(new_email)):
                    print("Invalid email.")
                    return
                confirm_email = input("Confirm changes? [y/N] ")
                if confirm_email == "y":
                    cur = con.cursor()
                    cur.execute(
                        """
                        UPDATE "users"
                        SET "personal_email" = ?
                        WHERE "id" = ?
                        """,
                        (new_email, user_id)
                    )
                    con.commit()
                    print("Successfully updated personal email.")
                    return
                elif confirm_email == "n":
                    print("Failed to update your personal email.")
                    return
        else:
            print("The information you provided is incorrect.")
            return
    else:
        print("The information you provided is incorrect.")
        return

def update_password(user_id, get_email):
    tracker = geolocation()
    session_in = check_session_db(user_id)
    ip_address = tracker["query"]
    country = tracker["country"]
    status = tracker["status"]
    proxy = tracker["proxy"]
    hosting = tracker["hosting"]

    result = account_db(user_id)
    account_status = result["account_status"]
    verified_location = result["verified_location"]

    if account_status in BLOCKED_STATUSES:
        print("The system can't access your account. Please contact the admin.")
        return
    
    if is_local_ip(ip_address):
        security_logger("inconsistent_ip", user_id, ip_address, country, "Detected a proxy or hosting ip address")
        print("Sytem error. Please try again or contact the admin.")
        return
    
    if check_credential_stuffing(ip_address):
        edit_blacklist("add", None, ip_address, "Credential stuffing detected.", "system-auto")
        security_logger("credential_stuffing", user_id, ip_address, country, "Credential stuffing detected.")
        print("System error. Please try again or contact the admin.")
        return

    if is_suspicious_ip(status, proxy, hosting):
        security_logger("inconsistent_ip", user_id, ip_address, country, "Detected a proxy or hosting ip address")
        print("System error. Please try again or contact the admin.")
        return

    if verified_location != country:
        security_logger("new_country_login", user_id, ip_address, country, "Trying to login from a different country.") 
        print("System error. Please try again or contact the admin.")
        return
    
    if not session_in:
        print("You need to login to change your password. If you are having trouble logging in, please contact the admin or the customer service.")
        return
    elif session_in:
        if verify_old_password(get_email):
            if verify_otp(user_id, get_email, ip_address, country):
                change_password(user_id, get_email, account_status, "change password")
            return
        return
    
def change_password(user_id, email, account_status, notes):
    cur = con.cursor()
    
    while True:
        get_password = getpass.getpass("new password: ")
        if is_strong_password(get_password):
            retype_password = getpass.getpass("re-type new password: ")

            fetch_credentials = get_credentials(email)
            password_db = fetch_credentials["password"]
            
            bcrypt_new_pw = get_password.encode()
            bcrypt_pw_db = password_db.encode()

            if bcrypt.checkpw(bcrypt_new_pw, bcrypt_pw_db):
                print("Please use a different password.")
            
            elif get_password == retype_password:
                break
            else:
                "The password doesn't match. Please try again."
        else:
            print("[Password should be at least 12 characters long with at least one uppercase, lowercase, number, and special character.]")

    hashed = bcrypt.hashpw(get_password.encode(), bcrypt.gensalt()).decode()
    cur.execute(
        """
        UPDATE "users" 
        SET "password" = ?, "account_status" = ?, "notes" = ?, "changed_by" = ?
        WHERE "id" = ?
        """,
        (hashed, account_status, notes, user_id, user_id)
    )
    con.commit()      

def get_new_token(user_id, notes, admin_ip, admin_loc, changed_by):
    # for demo
    activation_token = secrets.token_hex(32)
    # print("Activation code:", activation_token)

    token_db = hashlib.sha256(activation_token.encode()).hexdigest()
    token_expiry = datetime.now(timezone.utc) + timedelta(hours=24)

    cur = con.cursor()
    cur.execute(
        """
        UPDATE "users" 
        SET "activation_token" = ?, "token_expiry" = ?, "notes" = ?, "changed_by" = ?
        WHERE "id" = ?
        """,
        (token_db, token_expiry, f"Reason:{notes}.\nAdmin_ip:{admin_ip} Admin_loc:{admin_loc}", changed_by, user_id)
    )
    con.commit()
    return print("Activation token:", activation_token)

def unlock_reset(user_id, notes, admin_ip, admin_loc, unlocked_by):
    cur = con.cursor()
    cur.execute(
        """
        UPDATE "users" 
        SET "account_status" = ?, "notes" = ?, "changed_by" = ?
        WHERE "id" = ?
        """,
        ('unlocked', f"Reason:{notes}.\nAdmin_ip:{admin_ip} Admin_loc:{admin_loc}", unlocked_by, user_id)
    )
    con.commit()
    return

def security_logger(anomaly, user_id, malicious_ip, detected_location, notes):
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO "security_events_logs" (anomaly, user_id, malicious_ip, detected_location, notes)
        VALUES (?, ?, ?, ?, ?)
        """,
        (anomaly, user_id, malicious_ip, detected_location, notes)
    )
    con.commit()
    return

def failed_login_count(user_id, from_date, now):
    cur = con.cursor()
    cur.execute(
        """
        SELECT COUNT("success") AS "attempts_week" FROM "login_attempts_logs" 
        WHERE "user_id" = ? AND "success" = ? AND "timestamp" BETWEEN ? AND ?
        """,
        (user_id, 0, from_date, now)
    )
    attempts_week = cur.fetchone()["attempts_week"]
    return attempts_week

def attempts_logs_recent(user_id):
    cur = con.cursor()
    now = datetime.now(timezone.utc)
    weeks_old = now - timedelta(days=7)    
    
    cur.execute(
        """
        SELECT "anomaly", "malicious_ip", "detected_location", "notes", "timestamp"
        FROM "security_events_logs"
        WHERE "user_id" = ? AND "timestamp" BETWEEN ? AND ?
        ORDER BY "timestamp" DESC
        """,
        (user_id, weeks_old, now)
    )
    recents = cur.fetchall()
    return recents

def attempts_logs_older(user_id):
    cur = con.cursor()
    now = datetime.now(timezone.utc)
    weeks_older = now - timedelta(days=7)
    month_old = now - timedelta(days=30)
    
    cur.execute(
        """
        SELECT "anomaly", "malicious_ip", "detected_location", "notes", "timestamp"
        FROM "security_events_logs"
        WHERE "user_id" = ? AND "timestamp" BETWEEN ? AND ?
        ORDER BY "timestamp" DESC
        """,
        (user_id, month_old, weeks_older)
    )
    older_records = cur.fetchall()
    if older_records is None:
        return None
    return older_records

def require_admin():
    get_email = input("admin email: ").lower()
    fetch_user = find_user(get_email)
    if fetch_user is None:
        print("The login information you entered is incorrect. If you are having trouble please contact the admin or the customer service.")
        return None
    user_id = fetch_user["id"]
    role = fetch_user["role"]

    tracker = geolocation()
    ip_address = tracker["query"] 
    country = tracker["country"]

    session_in = check_session_db(user_id)
    if not session_in:
        print("The information you provided is incorrect.")
        return None
    if session_in:
        if role != "admin":
            print("Access denied.")
            return None
        return {"session_in": session_in, "user_id": user_id, "role": role, "ip_address": ip_address, "country": country}

if __name__ == "__main__":
    main()

# otps are sent to company email that's only accessible in the workplace || tokens are sent to personal emails -- activation and forgot password
# should have trusted network list
# device detector for location change validation
# create an mail to send activaton token
# applicants list -- personal email and phonenumber source