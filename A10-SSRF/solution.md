# SSRF Challenge Solution

## Overview
This document explains how to solve the Server-Side Request Forgery (SSRF) challenge. The vulnerable application allows users to fetch content from a URL, but it doesn't properly validate the URL, enabling an attacker to access internal services and resources.

## Vulnerability Analysis
The vulnerability exists in the `validate_url()` function in `app.py`. Let's look at the vulnerable code:

```python
def validate_url(url):
    parsed_url = urlparse(url)
    
    # Basic validation only - VULNERABLE TO SSRF
    if not parsed_url.scheme or not parsed_url.netloc:
        return False
    
    # No proper validation for internal IPs - VULNERABLE
    return True
```

This function only checks if the URL has a scheme (e.g., http, https) and a netloc (e.g., example.com), but doesn't validate if the URL points to internal services like localhost or internal IP addresses.

## Step-by-Step Solution

### 1. Reconnaissance
1. Open the application at http://localhost:5001
2. Observe the "File Downloader Tool" that allows users to input a URL and download the file from that URL

### 2. Initial Testing
1. Test the application with a valid external URL (e.g., http://example.com)
2. Verify that the application downloads the content and shows a download link

### 3. Discovering the Internal Service
From the Dockerfile and start.sh, we can see that an internal service runs on port 745. This service likely hosts the flag file.

### 4. Exploiting the SSRF Vulnerability
1. Enter `http://localhost:745/` in the URL input field
2. Click "Fetch File"
3. The application will make a request to the local service
4. The downloaded file will contain the directory listing of the internal service

### 5. Finding the Flag
1. After seeing the directory listing, enter `http://localhost:745/flag.txt` in the URL input field
2. Click "Fetch File"
3. The application will fetch the flag.txt file from the internal service
4. Download the file to view the flag: `VNPT{SSRF_1s_D4ng3r0us_F0r_1ntern4l_S3rvic3s}`

### 6. Alternative Methods
If the `localhost` is blocked or doesn't work, try the following alternatives:
1. Use IP address `127.0.0.1` instead of `localhost`: `http://127.0.0.1:745/flag.txt`
2. Use IPv6 localhost: `http://[::1]:745/flag.txt`
3. Use other loopback addresses: `http://127.0.0.2:745/flag.txt`

## Mitigation Strategies
To prevent SSRF vulnerabilities, implement the following safeguards:

1. **Whitelist Validation**: Only allow requests to approved domains or IP addresses
2. **Block Internal IPs**: Block requests to private IP ranges and loopback addresses
3. **Disable Redirects**: Don't follow redirects or limit the number of redirects
4. **Use a Proxy**: Route external requests through a proxy that enforces access control
5. **Restrict Ports**: Only allow standard ports (e.g., 80, 443)
6. **Input Validation**: Validate all user-supplied URLs before processing

## Recommended Code Fix
Replace the vulnerable validation function with this secure version:

```python
def validate_url(url):
    parsed_url = urlparse(url)
    
    # Check for scheme and netloc
    if not parsed_url.scheme or not parsed_url.netloc:
        return False
    
    # Check for localhost and private IP ranges
    try:
        host = parsed_url.netloc.split(':')[0]
        ip = socket.gethostbyname(host)
        
        # Reject loopback addresses
        if ip.startswith('127.') or ip == '::1':
            return False
            
        # Reject private IP ranges
        private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
        ]
        
        ip_addr = ipaddress.ip_address(ip)
        for network in private_ranges:
            if ip_addr in network:
                return False
                
        return True
    except:
        return False
```

## Conclusion
This challenge demonstrates how SSRF vulnerabilities can be used to access internal services that shouldn't be accessible from outside. By crafting a malicious URL that points to a local service, an attacker can potentially access sensitive information, internal APIs, or other restricted resources.

Always implement proper URL validation to prevent SSRF attacks. 