import os
import sys
import re
import time
import json
import sqlite3
import bcrypt
import logging
from logging.handlers import RotatingFileHandler
from contextlib import closing


# =========================
#  Masked password input  *
# =========================
# Cross-platform masked input that shows '*' for each typed char.
# On macOS/Linux uses termios; on Windows uses msvcrt.
# Falls back to getpass (no echo) or input (visible) if necessary.

def _posix_getpass_masked(prompt: str) -> str:
    import termios, tty  # imported here to keep Windows happy
    sys.stdout.write(prompt)
    sys.stdout.flush()
    fd = sys.stdin.fileno()

    # Save current terminal settings
    old = termios.tcgetattr(fd)

    # New settings: no echo, non-canonical (char-by-char)
    new = termios.tcgetattr(fd)
    new[3] = new[3] & ~termios.ECHO & ~termios.ICANON  # lflags: disable ECHO & ICANON
    new[6][termios.VMIN] = 1
    new[6][termios.VTIME] = 0

    buf = ""
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, new)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\r", "\n"):  # ENTER
                sys.stdout.write("\n")
                return buf
            if ch == "\x03":  # Ctrl-C
                raise KeyboardInterrupt
            if ch in ("\x7f", "\b"):  # Backspace
                if buf:
                    buf = buf[:-1]
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            # ignore other control chars
            if ord(ch) < 32:
                continue
            buf += ch
            sys.stdout.write("*")
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _windows_getpass_masked(prompt: str) -> str:
    import msvcrt  # windows-only
    sys.stdout.write(prompt)
    sys.stdout.flush()
    buf = ""
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):  # ENTER
            sys.stdout.write("\n")
            return buf
        if ch == "\x03":  # Ctrl-C
            raise KeyboardInterrupt
        if ch == "\x08":  # Backspace
            if buf:
                buf = buf[:-1]
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            continue
        if ord(ch) < 32:  # control chars
            continue
        buf += ch
        sys.stdout.write("*")
        sys.stdout.flush()


def prompt_password(prompt: str) -> str:
    """
    Unified password prompt:
    1) masked '*' (POSIX/Windows) if in a real TTY,
    2) falls back to getpass (no echo),
    3) last resort: input visible (explicit warning).
    """
    try:
        if sys.stdin.isatty() and sys.stdout.isatty():
            if os.name == "nt":
                return _windows_getpass_masked(prompt).strip()
            else:
                return _posix_getpass_masked(prompt).strip()
    except Exception:
        pass

    # Fallbacks
    try:
        import getpass, warnings
        from getpass import GetPassWarning
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=GetPassWarning)
            return getpass.getpass(prompt).strip()  # no echo
    except Exception:
        pass

    # Last resort (visible)
    return input(f"{prompt} (⚠️ visible): ").strip()


# ================
#  Configuration
# ================
DB_PATH = "auth.db"

# Security policy
MAX_ATTEMPTS = 3
INITIAL_LOCKOUT = 30  # seconds
BACKOFF_FACTOR = 2  # exponential backoff
MAX_LOCKOUT = 3600  # 1 hour
MAX_LOCKOUT_CYCLES = 3  # after that → require reset
MIN_ACCEPTED_SCORE = 3  # require >= Medium
BCRYPT_COST_ROUNDS = 12  # bcrypt work factor (12 is a good local default)

# Common password blacklist (short sample)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "baseball", "football", "letmein", "monkey"
}


# ==================
#  DB Initialization
# ==================
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username       TEXT PRIMARY KEY,
            password_hash  TEXT NOT NULL,
            attempts       INTEGER NOT NULL DEFAULT 0,
            lockout_until  INTEGER NOT NULL DEFAULT 0,
            lockout_cycles INTEGER NOT NULL DEFAULT 0
        )
        """)
        conn.commit()

    # Optional: restrict file permissions on POSIX (owner read/write)
    try:
        if os.name != "nt":
            import stat
            os.chmod(DB_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

 ####### Delete function
def delete_user(username: str):
    """Supprime un utilisateur de la base"""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()

def interactive_delete():
    u = input("Username to delete (or 'cancel' to go back): ").strip().lower()
    if u == "cancel":
        print("❌ Deletion cancelled.")
        return

    user = get_user(u)
    if not user:
        print(f"❗ User '{u}' not found.")
        return

    confirm = input(f"⚠️ Are you sure you want to delete '{u}'? (yes/no): ").strip().lower()
    if confirm == "yes":
        delete_user(u)
        logger.info(f"DELETE user username={u}")
        print(f"✅ User '{u}' deleted successfully.")
    else:
        print("❌ Deletion aborted.")


# =======================
#  Hashing & Verification
# =======================
def hash_password_bcrypt(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"),
                         bcrypt.gensalt(BCRYPT_COST_ROUNDS)).decode("utf-8")


def verify_password_bcrypt(stored_hash: str, provided_password: str) -> bool:
    try:
        return bcrypt.checkpw(provided_password.encode("utf-8"),
                              stored_hash.encode("utf-8"))
    except Exception:
        return False


# =======================
#  Password Strength Meter
# =======================
def password_strength(password: str) -> tuple[int, str, list[str]]:
    score = 0
    tips = []

    if len(password) >= 8:
        score += 1
    else:
        tips.append("Use at least 8 characters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        tips.append("Add a lowercase letter")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        tips.append("Add an uppercase letter")

    if re.search(r"\d", password):
        score += 1
    else:
        tips.append("Add a number")

    if re.search(r"[^\w\s]", password):
        score += 1
    else:
        tips.append("Add a special character (e.g. !, $, %)")

    # Penalties
    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 3)
        tips.append("Avoid common passwords")
    if len(password) < 6:
        score = max(0, score - 2)

    if score == 5:
        cat = "Strong"
    elif score == 4:
        cat = "Medium"
    elif score == 3:
        cat = "Weak"
    else:
        cat = "Very Weak"

    return score, cat, tips


def print_strength_bar(score: int):
    total = 5
    bar = "█" * score + "░" * (total - score)
    if score >= 4:
        color = "\033[92m"  # green
    elif score == 3:
        color = "\033[93m"  # yellow
    else:
        color = "\033[91m"  # red
    reset = "\033[0m"
    print(f"Strength: {color}{bar} ({score}/5){reset}")


# ==============
#  DB Utilities
# ==============
def now() -> int:
    return int(time.time())


def get_user(username: str) -> dict | None:
    with sqlite3.connect(DB_PATH) as conn, closing(conn.cursor()) as cur:
        cur.execute("""
            SELECT username, password_hash, attempts, lockout_until, lockout_cycles
            FROM users WHERE username = ?""", (username.lower(),))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "username": row[0],
            "password_hash": row[1],
            "attempts": row[2],
            "lockout_until": row[3],
            "lockout_cycles": row[4],
        }


def create_user(username: str, password_hash: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username.lower(), password_hash)
        )
        conn.commit()


def update_user_fields(username: str, **fields):
    if not fields:
        return
    keys = ", ".join([f"{k} = ?" for k in fields.keys()])
    values = list(fields.values()) + [username.lower()]
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(f"UPDATE users SET {keys} WHERE username = ?", values)
        conn.commit()


# ==================
#  Lockout Mechanics
# ==================
def is_locked(user: dict) -> bool:
    return now() < user["lockout_until"]


def remaining_lock_seconds(user: dict) -> int:
    return max(0, user["lockout_until"] - now())


def apply_lockout(user: dict) -> int:
    cycles = user["lockout_cycles"]
    duration = min(MAX_LOCKOUT, int(INITIAL_LOCKOUT * (BACKOFF_FACTOR ** cycles)))
    update_user_fields(
        user["username"],
        lockout_cycles=cycles + 1,
        lockout_until=now() + duration,
        attempts=0
    )
    return duration


def simulate_send_reset_email(username: str):
    print(
        f"[SIMULATION] Password reset email sent to user '{username}'. Please follow the link to unlock and set a new password.")


# ================
#  Register / Login
# ================
def interactive_register():
    while True:
        u = input("Username (or 'cancel' to go back): ").strip().lower()
        if u == "cancel":
            print("Registration cancelled.")
            return
        if not u:
            print("Username cannot be empty.");
            continue
        if get_user(u):
            print(f"❗ The username '{u}' already exists.");
            continue

        while True:
            p1 = prompt_password("Password (or 'cancel' to abort): ")
            if p1.lower() == "cancel":
                print("Password entry cancelled.");
                break

            p2 = prompt_password("Confirm password: ")
            if p1 != p2:
                print("❌ Passwords do not match. Try again.");
                continue

            score, cat, tips = password_strength(p1)
            print_strength_bar(score);
            print(f"Password category: {cat}")
            if score < MIN_ACCEPTED_SCORE:
                print("❌ Password too weak. Suggestions:")
                for t in tips: print("   -", t)
                continue

            try:
                create_user(u, hash_password_bcrypt(p1))
                logger.info(f"REGISTER success username={u}")
                print(f"✅ User '{u}' registered successfully.")
            except sqlite3.IntegrityError:
                logger.warning(f"REGISTER conflict username={u}")
                print("❗ Username already exists (race condition). Try again.")
                continue
            return


def login_flow():
    u = input("Username: ").strip().lower()
    user = get_user(u)
    if not user:
        print("❗ User not found. Use register first.")
        return

    if is_locked(user):
        rem = remaining_lock_seconds(user)
        logger.info(f"LOGIN denied_locked username={u} remaining={rem}s cycles={user['lockout_cycles']}")
        print(f"🚫 Account locked. Try again in {rem} second(s).")
        if user["lockout_cycles"] >= MAX_LOCKOUT_CYCLES:
            print("⚠️ Max lockout cycles reached. Email reset required (simulated).")
        return

    print(f"You have up to {MAX_ATTEMPTS} attempts.")
    while True:
        attempt = prompt_password("🔑 Enter your password (or type 'quit' to cancel): ")
        if attempt.lower() == "quit":
            logger.info(f"LOGIN cancel username={u}")
            print("Login cancelled.")
            return

        user = get_user(u)  # refresh from DB
        if verify_password_bcrypt(user["password_hash"], attempt):
            print("✅ Access granted!")
            logger.info(f"LOGIN success username={u}")
            update_user_fields(u, attempts=0, lockout_cycles=0, lockout_until=0)
            return
        else:
            new_attempts = user["attempts"] + 1
            remaining = MAX_ATTEMPTS - new_attempts
            if remaining > 0:
                logger.warning(f"LOGIN failed username={u} attempts={new_attempts}")
                print(f"❌ Wrong password. {remaining} attempt(s) left.")
                update_user_fields(u, attempts=new_attempts)
            else:
                duration = apply_lockout(user | {"attempts": new_attempts})
                logger.warning(
                    f"LOCKOUT applied username={u} duration={duration}s cycles={get_user(u)['lockout_cycles']}")
                print(f"🚫 Too many failed attempts. Locked for {duration} second(s).")
                if get_user(u)["lockout_cycles"] >= MAX_LOCKOUT_CYCLES:
                    simulate_send_reset_email(u)
                return


# ==========
#  Inspect / Reset helpers
# ==========
def inspect_users():
    with sqlite3.connect(DB_PATH) as conn, closing(conn.cursor()) as cur:
        cur.execute("SELECT username, attempts, lockout_until, lockout_cycles FROM users ORDER BY username")
        rows = cur.fetchall()
        if not rows:
            print("(no users)")
            return
        print("username | attempts | lockout_until | lockout_cycles")
        for r in rows:
            print(f"{r[0]:8s} | {r[1]:8d} | {r[2]:13d} | {r[3]:14d}")


def reset_user():
    u = input("Username to reset: ").strip().lower()
    user = get_user(u)
    if not user:
        print("❗ User not found.");
        return
    update_user_fields(u, attempts=0, lockout_until=0, lockout_cycles=0)
    logger.info(f"RESET user username={u}")
    print(f"✅ '{u}' has been reset (attempts & lockout cleared).")


# =====
#  CLI
# =====
if __name__ == "__main__":
    # Logging: fichier tournant 1 Mo x 3 fichiers
    LOG_PATH = "auth.log"
    logger = logging.getLogger("auth")
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    init_db()
    print("Secure password auth (SQLite + bcrypt + strength + lockout).")
    while True:
        action = input("\nChoose: [register/login/inspect/delete/exit] > ").strip().lower()
        if action == "register":
            interactive_register()
        elif action == "login":
            login_flow()
        elif action == "inspect":
            with sqlite3.connect(DB_PATH) as conn, closing(conn.cursor()) as cur:
                cur.execute("SELECT username, attempts, lockout_until, lockout_cycles FROM users ORDER BY username")
                rows = cur.fetchall()
                if not rows:
                    print("(no users)")
                else:
                    print("username | attempts | lockout_until | lockout_cycles")
                    for r in rows:
                        print(f"{r[0]:8s} | {r[1]:8d} | {r[2]:13d} | {r[3]:14d}")
        elif action == "delete":
            interactive_delete()
        elif action == "exit":
            print("Goodbye.")
            break
        else:
            print("Unknown command. Use register, login, inspect, delete or exit.")

