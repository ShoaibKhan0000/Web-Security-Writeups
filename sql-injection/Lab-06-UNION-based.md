## Title
SQL Injection (UNION-based) in 'category' parameter — Cross-Table Data Retrieval

## Severity
Critical (9.8)

## Summary
The product category filter is vulnerable to UNION-based SQL injection...

## Affected Endpoint 
```sql
GET /filter?category=<input>
```
## Root Cause 
```sql
SELECT * FROM products WHERE category = '<user_input>'
```
## Payload
```sql
'UNION SELECT username, password FROM users--
```

## Payload Breakdown
- `'` (single quote): closes the original backend SQL query string.
- `UNION`: appends a second, attacker-controlled query to the original query's output.
- `SELECT username, password FROM users`: pulls usernames and passwords from the `users` table instead of `products`.
- `--`: comments out the rest of the original query so it doesn't cause a syntax error.

## Steps to Reproduce

1. Confirm the query returns 2 text-compatible columns (established via `'UNION SELECT 'a','b'--`).
2. Modify the `category` parameter to `'UNION SELECT username, password FROM users--`.
3. Observe the response — it lists `carlos`, `administrator`, and `wiener` with their passwords.
4. Use the leaked `administrator` password to log in via the login page.
5. Confirm successful login as `administrator`.

## Evidence
<img width="1920" height="1200" alt="Pasted image 20260915060924" src="https://github.com/user-attachments/assets/911394e8-a56d-44dc-b114-07bb3946fa2e" />
<img width="1920" height="1200" alt="Pasted image 20260915060959" src="https://github.com/user-attachments/assets/57d1762c-771e-4e30-a822-a635e9454a31" />

## Impact
An attacker can extract the entire `users` table, including the
administrator's password, leading to full account takeover.

## Remediation
- Use parameterized queries (prepared statements). Do not add user input directly into SQL queries.
- Apply the principle of least privilege to the database account used by the application.
- Show a generic error message instead of a detailed database error.
