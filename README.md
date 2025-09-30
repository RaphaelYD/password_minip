## password_minip
Secure password authentication system built in **Python** with:
- **SQLite** (for persistent user storage)
- **bcrypt** (for secure password hashing)
- **Logging** (audit trail of actions)
- **Unit tests (pytest)**
  
---

##  Features
- Register users with strong password requirements  
- Login system with attempt counter and exponential lockout  
- Delete users  
- Password strength meter (with live feedback in CLI)  
- Logging of all important events (success, failure, lockout)  
- Unit tests included  

---

##  Installation

Clone the repository:
'''bash 
git clone https://github.com/RaphaelYD/password_minip.git
cd password_minip

Create a virtual environment and install dependencies:

python3 -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows

pip install -r requirements.txt

---

##  Usage

Start the authentication CLI:
'''bash
python auth_sqlite.py

---

##  Options

- register → Create a new account
- login → Login with username and password
- inspect → View stored users (debug/admin only)
- delete → Remove a user
- exit → Quit the program

---

## Running Tests

  Run all unit tests:
    pytest -v

---

## Logging

  All events are logged into auth.log.
    Example entries:
      - 2025-09-30 16:00:12 INFO REGISTER success username=alice
      - 2025-09-30 16:01:45 WARNING LOGIN failed username=alice attempts=1
      - 2025-09-30 16:02:30 INFO LOGIN success username=alice.

---

## Contributing

    Pull requests are welcome! For major changes, open an issue first to discuss what you would like to change.
     License
      MIT License
















