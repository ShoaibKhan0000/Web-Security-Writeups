# Title

SQL Injection (UNION-based) — Querying the Database Type and Version

# Severity

Medium (5.3) — Information Disclosure

This finding by itself only discloses database metadata (type/version), not sensitive user data. However, it aids an attacker in planning further, more severe attacks (e.g., exploiting known CVEs for that specific database version).

# Summary

The product category filter is vulnerable to UNION-based SQL injection. By injecting a payload that calls the database's built-in version function, the database type and version string were extracted directly in the application's response.

# Affected Endpoint

    GET /filter?category=<input>

# Root Cause

    SELECT * FROM products WHERE category = '<user_input>'

# Payload

    'UNION SELECT @@version,NULL#

# Payload Breakdown

- `'` (single quote): closes the original backend SQL query string.
- `UNION SELECT`: appends a second, attacker-controlled query to the original query's output.
- `@@version`: a built-in variable in MySQL that returns the database version string.
- `NULL`: placeholder for the second column — kept NULL because it isn't needed in the output.
- `#`: comments out the rest of the original query (MySQL-style comment).

# Steps to Reproduce

1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns and confirm which ones accept text data, using: `'UNION SELECT 'abc','def'#`.
3. Replace one of the text columns with `@@version` to display the database version: `'UNION SELECT @@version,NULL#`.
4. Observe the response — the database version string appears directly on the page (e.g., `8.0.42-0ubuntu0.20.04.1`).

# Evidence

<img width="1920" height="1200" alt="Pasted image 20260915062052" src="https://github.com/user-attachments/assets/72023728-4d68-45a1-b7c6-58e6c6f6f097" />


# Impact

An attacker can fingerprint the exact database type and version in use. This information helps in crafting version-specific exploits (known CVEs for that DB version) and in tailoring further SQL injection payloads to that database's specific syntax.

# Remediation

- Use parameterized queries (prepared statements). Do not add user input directly into SQL queries.
- Apply the principle of least privilege to the database account used by the application.
- Show a generic error message instead of a detailed database error.
- Disable verbose database error/version disclosure in production.
