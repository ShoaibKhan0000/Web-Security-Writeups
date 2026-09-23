# SQL Injection in Login Page (Login Bypass)

**Target:** PortSwigger Web Security Academy (SQL injection lab)
**Vulnerability Class:** SQL Injection (CWE-89)

## Summary
The login page is vulnerable to SQL injection. When I entered `administrator'--` as the username and any text as the password, I was logged in as administrator without knowing the real password.

## Affected Endpoint
`POST /login`

The `username` field is vulnerable because the application puts my input directly into the SQL query.

## Root Cause
The application does not check or clean the user input before using it in the SQL query. The query probably looks like this:

```sql
SELECT * FROM users WHERE username = '<input>' AND password = '<input>'
```

## Payload
```
Username: administrator'--
Password: anything
```

## Payload Breakdown
- `administrator` is a valid username.
- `'` closes the username text in the query.
- `--` starts a SQL comment, so the rest of the query (the password check) is ignored.

## Steps to Reproduce
1. Open the login page.
2. Enter a normal username and password, for example `administrator` and `1234`. The login fails and shows an error.
3. Now enter `administrator'--` as the username and any text as the password.
4. Click **Log in**. You are logged in as administrator.

<img width="1920" height="1200" alt="Pasted image 20260914165638" src="https://github.com/user-attachments/assets/8ab6a0db-6afa-4e30-a326-682696a758fd" />


## Impact
An attacker can log in as any user, including the administrator, without knowing the password. This can lead to account takeover and access to private data.

## Remediation
- Use parameterized queries (prepared statements). Do not add user input directly into SQL queries.
- Store passwords as hashes and check them in the application code.
- Show a simple error message like "Invalid username or password."
