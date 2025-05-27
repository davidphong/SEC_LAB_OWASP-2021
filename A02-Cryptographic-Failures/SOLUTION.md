# Cryptographic Failures (A02) Lab - Solution Guide

## Vulnerability Description

This lab demonstrates two common Cryptographic Failures vulnerabilities:

1. **Weak Hashing Algorithm**: The application uses MD5, a weak and deprecated hashing algorithm, for storing passwords in a database backup file.

2. **Exposed Credentials**: The application stores a database backup file with sensitive information in a publicly accessible location, which can be discovered through directory scanning.

## Exploitation Steps

### Step 1: Directory Scanning to Find Hidden Files

First, we need to find the hidden backup file in the web application. We can use directory scanning tools like `dirsearch` or `gobuster` to discover it.

```bash
# Using dirsearch
python3 dirsearch.py -u http://target-website:5000 -e bak,backup,old,db,sql,txt,log

# Using gobuster
gobuster dir -u http://target-website:5000 -w /usr/share/wordlists/dirb/common.txt -x bak,backup,old,db,sql,txt,log
```

This scan should discover a file at `/static/db_backup.bak`.

### Step 2: Analyze the Backup File

After discovering the backup file, we can access it directly in our browser:

```
http://target-website:5000/static/db_backup.bak
```

The backup file contains user information including usernames, emails, and password hashes. Additionally, there's a revealing comment that exposes the admin's password:

```
# Database Backup - CONFIDENTIAL
# Date: 2023-08-01 12:34:56

# User accounts (username, email, md5_password)

admin,admin@lab,21232f297a57a5a743894a0e4a801fc3
guest,guest@lab,84983c60f7daadc1cb8698621f802c0d
# Note: admin password hash needs to be updated to new format (current: admin123)

# End of backup
```

The comment reveals two critical pieces of information:
1. The backup uses MD5 hashing (a weak algorithm)
2. The admin password is "admin123"

### Step 3: Crack the MD5 Hash (Alternative Approach)

If the comment hadn't directly revealed the password, we could crack the MD5 hash using various methods:

1. **Using Online MD5 Crackers**:
   Several online services can quickly look up MD5 hashes in their databases:
   - https://crackstation.net/
   - https://hashkiller.io/
   - https://md5decrypt.net/

   Input the hash `21232f297a57a5a743894a0e4a801fc3` and these services would return "admin123".

2. **Using Hashcat**:
   ```bash
   hashcat -m 0 -a 0 21232f297a57a5a743894a0e4a801fc3 /path/to/wordlist.txt
   ```

3. **Using John the Ripper**:
   ```bash
   echo "21232f297a57a5a743894a0e4a801fc3" > hash.txt
   john --format=raw-md5 --wordlist=/path/to/wordlist.txt hash.txt
   ```

### Step 4: Login as Admin

With the admin password "admin123" discovered, we can log in to the admin account:

1. Navigate to the login page
2. Enter username: `admin`
3. Enter password: `admin123`
4. Submit the form

After successful login, we can access the admin page and retrieve the flag:

```
FLAG{Weak_Hashing_Algorithm_Leads_To_Password_Compromise}
```

## Code Vulnerabilities

### Vulnerable Code: Creating Backup with Weak Hashing

The vulnerability is in the `create_db_backup` function in `app.py`:

```python
def create_db_backup():
    """Create a backup file with credentials using a weak hashing algorithm (MD5)"""
    backup_path = os.path.join(app.static_folder, 'db_backup.bak')
    with open(backup_path, 'w') as f:
        f.write("# Database Backup - CONFIDENTIAL\n")
        f.write("# Date: {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        f.write("# User accounts (username, email, md5_password)\n\n")
        
        users = User.query.all()
        for user in users:
            # Use weak MD5 hashing for the backup "for storage efficiency"
            weak_hash = hashlib.md5(user.username.encode()).hexdigest()
            f.write(f"{user.username},{user.email},{weak_hash}\n")
            
            # For the admin user, include the real hash
            if user.username == "admin":
                # "accidentally" include the actual password in a comment
                f.write(f"# Note: admin password hash needs to be updated to new format (current: admin123)\n")
                
        f.write("\n# End of backup\n")
```

This function has two critical issues:
1. It uses MD5, a cryptographically weak algorithm, for hashing passwords in the backup
2. It places the backup file in a publicly accessible directory (`/static/`)
3. It directly comments the admin password in plaintext

## Remediation

### Fix for Weak Hashing

To fix the weak hashing vulnerability, use a modern, secure hashing algorithm with proper salting:

```python
def create_db_backup():
    # Use a secure location that's not web-accessible
    backup_path = os.path.join('secure_backups', f'db_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.bak')
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    
    with open(backup_path, 'w') as f:
        f.write("# Database Backup - CONFIDENTIAL\n")
        f.write("# Date: {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        f.write("# User accounts (username, email)\n\n")
        
        users = User.query.all()
        for user in users:
            # Only store non-sensitive information
            f.write(f"{user.username},{user.email}\n")
                
        f.write("\n# End of backup\n")
```

### Fix for Exposed Credentials

To fix the exposed credentials vulnerability:

1. **Don't store sensitive data in backups**:
   - Never include passwords (even hashed) in backups
   - If password hashes are necessary, use a secure hashing algorithm with salting

2. **Secure backup storage**:
   - Store backups in a location not accessible from the web
   - Use access controls to restrict who can access backups
   - Encrypt backup files

3. **Implement secure backup procedures**:
   - Automate backup creation and storage
   - Regularly rotate and delete old backups
   - Monitor and log access to backup files

## Learning Points

1. **Use strong hashing algorithms** - Modern password hashing should use algorithms like bcrypt, Argon2, or PBKDF2, not MD5 or SHA1
2. **Implement proper salting** - Each password should have a unique salt to prevent rainbow table attacks
3. **Secure backup storage** - Never store backups in web-accessible locations
4. **Protect sensitive data** - Never include plaintext credentials or weak hashes in backups
5. **Directory scanning protection** - Implement proper web server configurations to prevent directory scanning
6. **Regular security audits** - Regularly scan for exposed sensitive files

The flag for this challenge is: `FLAG{Weak_Hashing_Algorithm_Leads_To_Password_Compromise}` 