# Title

Blind SQL Injection — Conditional Responses via TrackingId Cookie

# Severity

High (7.5) — Authentication Bypass / Full Data Extraction

This finding allows an attacker to extract the administrator's password character-by-character without ever seeing the raw data or any database error, leading to complete account takeover.

# Summary

The `TrackingId` cookie (used for analytics) is passed directly into a SQL query on the backend. The query's result is never shown in the response, and no error messages are returned — but the application displays a `Welcome back` message whenever the injected condition evaluates to true. This conditional difference in the response was used as a boolean oracle to extract the administrator's password one character at a time.

# Affected Endpoint

```
GET / HTTP/2
Cookie: TrackingId=<input>
```

Parameter: `TrackingId` cookie

# Root Cause

Backend query concatenates the cookie value directly into a SQL statement without parameterization:

```sql
SELECT * FROM tracking WHERE id = '<cookie_value>'
```

# Payload

```
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```

# Payload Breakdown

- `'` (single quote): closes the original `id` string in the backend query.
- `AND (SELECT ... )='a'`: a boolean sub-query — if the extracted character equals `a`, the overall condition is true.
- `SUBSTRING(password,1,1)`: extracts one character of the password at a given position.
- `username='administrator'`: targets the specific user whose password is being extracted.
- The final `'a'` is the guessed character being tested; this is swapped for each letter/digit during the attack.
- No comment (`--` or `#`) is needed here since the rest of the original query (`AND ...`) still makes sense appended after.

# Steps to Reproduce

1. Visit the front page of the shop and use Burp Suite to intercept the request containing the `TrackingId` cookie.
2. Confirm boolean-based blind SQLi by testing a true vs. false condition:
   - `TrackingId=xyz' AND '1'='1` → `Welcome back` message appears.
   - `TrackingId=xyz' AND '1'='2` → `Welcome back` message disappears.
3. Confirm the `users` table exists:
   `TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`
4. Confirm a user called `administrator` exists:
   `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a`
5. Determine the password length by testing `LENGTH(password) > N` with increasing values of `N` until the condition turns false. Length found: **20 characters**.
6. Use Burp Intruder (Sniper attack) to extract the password character by character:
   ```
   TrackingId=xyz' AND (SELECT SUBSTRING(password,%s,1) FROM users WHERE username='administrator')='%s
   ```
   - First payload position (`%s`) = character offset, tested 1 to 20
   - Second payload position (`%s`) = candidate character, tested a-z and 0-9
7. Set a Grep - Match rule for the string `Welcome back` in the Settings panel, so Intruder flags which response contains it.
8. Launch the attack. For each offset, the row where `Welcome back` is ticked reveals the correct character at that position.
9. Repeat for all 20 positions and assemble the full password.
10. Log in as `administrator` using the extracted password to confirm the attack worked.

# Evidence
<img width="1920" height="1200" alt="Pasted image 20260917213548" src="https://github.com/user-attachments/assets/0611a6e9-a4dc-4970-bf7d-92dc4a15d528" />
<img width="1920" height="1200" alt="Pasted image 20260917213345" src="https://github.com/user-attachments/assets/2e7d68e1-e619-4186-b186-0854477034bd" />

- Burp Intruder results table showing one row per offset with the `Welcome back` column ticked, confirming the correct character at each position.
- Extracted password: `1zys8kh15d1q6bbbmb6x`
- Successful login as `administrator` using the extracted credentials.

# Impact

An attacker can perform full boolean-based blind data extraction — including admin credentials — without relying on visible query output or database error messages. This leads to complete authentication bypass and account takeover of the `administrator` user, and the same technique could be extended to dump any other table/column in the database.

# Remediation

- Use parameterized queries (prepared statements). Do not concatenate cookie or any user-controlled input directly into SQL queries.
- Apply the principle of least privilege to the database account used by the application.
- Avoid conditionally rendering content (like "Welcome back") based on raw query success/failure tied to attacker-controlled input.
- Monitor and rate-limit requests with abnormal cookie values to slow down automated blind SQLi extraction attempts.
