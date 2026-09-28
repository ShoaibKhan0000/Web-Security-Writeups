# SQL Injection UNION Attack - Determining Number of Columns

**Target:** PortSwigger Web Security Academy (SQL injection lab)
**Vulnerability Class:** SQL Injection (CWE-89)

## Summary

The product category filter is vulnerable to SQL injection. By submitting a series of UNION SELECT payloads with an increasing number of NULL values, I was able to determine that the underlying query returns 3 columns.

## Affected Endpoint

    GET /filter?category=<input>

The `category` parameter is vulnerable because the application puts my input directly into the SQL query.

## Root Cause

The application does not check or clean the user input before using it in the SQL query. The query probably looks like this:

    SELECT * FROM products WHERE category = '<input>'

## Payload

    'UNION SELECT NULL--
    'UNION SELECT NULL,NULL--
    'UNION SELECT NULL,NULL,NULL--

## Payload Breakdown

- `'` closes the category string in the query.
- `UNION SELECT NULL,...` tries to add a second query that returns only NULL values.
- The number of NULLs is increased one at a time until it matches the number of columns in the original query.
- `--` starts a SQL comment, so the rest of the original query is ignored.

## Steps to Reproduce

1. Use Burp Suite to intercept the request that sets the product category filter.
2. Modify the `category` parameter to `'UNION SELECT NULL--`. Result: Internal Server Error (column count does not match).
3. Modify the `category` parameter to `'UNION SELECT NULL,NULL--`. Result: Internal Server Error again (still does not match).
4. Modify the `category` parameter to `'UNION SELECT NULL,NULL,NULL--`. Result: Page loads normally, no error.
5. This confirms the query returns 3 columns.

## Impact

Confirming the column count is the first step toward a full UNION-based SQL injection attack, which can let an attacker extract data from other tables in the database (usernames, passwords, etc.).

## Remediation

- Use parameterized queries (prepared statements). Do not add user input directly into SQL queries.
- Apply the principle of least privilege to the database account used by the application.
- Show a generic error message instead of a detailed database error.

<img width="1920" height="1200" alt="Pasted image 20260915053800" src="https://github.com/user-attachments/assets/9cac1a88-4af2-4b49-b0eb-1dfdf26bead7" />
