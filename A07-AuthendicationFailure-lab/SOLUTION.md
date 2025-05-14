# Broken Authentication (A07) Lab - Solution Guide

## Vulnerability Description

This lab demonstrates two common Broken Authentication vulnerabilities:

1. **Username Enumeration**: During the registration process, the application reveals whether a username already exists, allowing attackers to enumerate valid usernames.

2. **Flawed Account Lockout Mechanism**: The application implements an account lockout feature that blocks access after three failed login attempts, but it has a logical flaw in its implementation - a successful login resets the failed attempt counter, making it vulnerable to brute force attacks.

## Exploitation Steps

### Vulnerability 1: Username Enumeration

1. **Attempt to register with existing usernames**:
   - Go to the registration page
   - Try to register with username "admin" (which we suspect exists)
   - Observe the error message: "Username already exists! Please choose a different username."
   - This confirms the username "admin" exists in the system

2. **Using this to enumerate users**:
   - You could create a list of potential usernames (wordlist)
   - Use a script or tool to attempt registration with each username
   - Record which usernames return the "already exists" error
   - This provides a list of valid usernames in the system

### Vulnerability 2: Flawed Account Lockout Mechanism

1. **Understanding the mechanism**:
   - The application locks an account for 1 minute after 3 consecutive failed login attempts
   - However, there's a logical flaw: a successful login resets the failed attempt counter

2. **Exploiting the vulnerability**:
   - When targeting the "admin" account, you can use the following pattern:
     - Try two incorrect passwords
     - Try a correct password for your own account (to reset the counter)
     - Repeat the process with two more incorrect passwords for "admin"
     - This way you can attempt many passwords without triggering the lockout

3. **Execute the attack**:
   - Set up a script or tool that follows this pattern
   - Use a password wordlist to try different passwords
   - The script should alternate between:
     - Two login attempts for "admin" with passwords from the wordlist
     - One successful login with your own account

4. **Sample exploit script (pseudocode)**:

```python
def exploit_auth_lockout(admin_wordlist):
    your_username = "your_account"
    your_password = "your_password"
    admin_username = "admin"
    
    for i in range(0, len(admin_wordlist), 2):
        # Try two passwords for admin
        attempt_login(admin_username, admin_wordlist[i])
        if i+1 < len(admin_wordlist):
            attempt_login(admin_username, admin_wordlist[i+1])
        
        # Reset counter with successful login
        attempt_login(your_username, your_password)
```

5. **Access the admin page**:
   - Once you've found the correct password for the admin account
   - Log in as admin and navigate to `/admin` to retrieve the flag

## Code Vulnerabilities

### Username Enumeration Vulnerability

The vulnerability is in the `register` route in `app.py`:

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Vulnerability: Specific error message reveals if username exists
        existing_user = User.query.filter_by(username=request.form["username"]).first()
        if existing_user:
            flash("Username already exists! Please choose a different username.", "danger")
            return render_template("register.html")
        
        # Rest of registration logic...
```

The application explicitly tells users when a username is already taken, which helps attackers identify valid accounts.

### Flawed Account Lockout Vulnerability

The vulnerability is in the `login` route in `app.py`:

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        
        # Account lockout check logic...
        
        # Find user in database
        u = User.query.filter_by(username=username).first()
        
        if u and u.chk_pw(request.form["password"]):
            # Vulnerability: Successful login resets the counter
            if username in failed_login_attempts:
                del failed_login_attempts[username]
            
            # Login success logic...
        else:
            # Failed login attempt tracking...
```

The application deletes the `failed_login_attempts` record after a successful login, which resets the counter completely instead of only incrementing/decrementing it.

## Remediation

### Fix for Username Enumeration

To fix the username enumeration vulnerability, use generic error messages that don't reveal whether the username exists:

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        existing_user = User.query.filter_by(username=request.form["username"]).first()
        if existing_user:
            # Generic message that doesn't confirm username exists
            flash("Registration failed. Please try again with different credentials.", "danger")
            return render_template("register.html")
        
        # Rest of registration logic...
```

### Fix for Flawed Account Lockout

To fix the account lockout mechanism, don't completely reset the counter on successful login, but rather implement a more sophisticated approach:

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        
        # Account lockout check logic...
        
        u = User.query.filter_by(username=username).first()
        
        if u and u.chk_pw(request.form["password"]):
            # Better approach: Gradually decrease counter instead of resetting
            if username in failed_login_attempts:
                # Reduce count by 1 instead of completely resetting
                failed_login_attempts[username]["attempts"] = max(0, failed_login_attempts[username]["attempts"] - 1)
                # Only remove if attempts reach 0
                if failed_login_attempts[username]["attempts"] == 0:
                    del failed_login_attempts[username]
            
            # Login success logic...
```

## Learning Points

1. **Use consistent error messages** - Don't reveal different messages for different error conditions during authentication
2. **Implement proper account lockout mechanisms** - Ensure they can't be bypassed or reset easily
3. **Consider rate limiting** - Limit authentication attempts based on IP addresses in addition to account-based lockouts
4. **Use multi-factor authentication** - For sensitive functions, implement MFA to provide an additional layer of security
5. **Monitor failed login attempts** - Track patterns that might indicate brute force attacks
6. **Implement CAPTCHA** - For login forms after a few failed attempts to prevent automated attacks

The flag for this challenge is: `VNPT{Broken_Authentication_Account_Lock_Bypass}` 