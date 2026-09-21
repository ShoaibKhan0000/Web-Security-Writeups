# SQL Injection in WHERE Clause — Retrieval of Hidden Data
**Target:** PortSwigger Web Security Academy Lab
**Vulnerability Class:** SQL Injection (CWE-89)

## Summary
Product filter endpoint directly concatenates user input into a SQL query without 
parameterization, allowing an attacker to bypass the `released = 1` condition and 
retrieve hidden/unreleased products.

## Affected Endpoint
`GET /filter?category=<user_input>`
<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/6ca4b494-3a26-4df6-90b3-f6028b07bb98" />



## Root Cause
Backend query:
`SELECT * FROM products WHERE category = '<user_input>' AND released = 1`


## Payload Breakdown
- `'` — closes the original string literal that the app opened around user input
- `--` — SQL single-line comment; comments out the rest of the original query 
  (including the `AND released = 1` check), so it never executes
- `OR 1=1` — a condition that's always true; when combined with the WHERE clause, 
  it makes every row match regardless of category, returning all products


## Steps to Reproduce
1. Observe normal request: `/filter?category=Corporate+gifts`
2. Inject a single quote to test: `category=Corporate+gifts'` → server error
   <img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/9880f187-c9e6-4995-8872-00021b42323d" />


3. Comment out rest of query: `category=Corporate+gifts'--` → 1 extra hidden product appears
 <img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/4bc983a8-098a-4dea-8277-0223ccff157f" />
  
4. Force full bypass: `category=Corporate+gifts'+OR+1=1--` → returns all products regardless of category/release status

<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/09acc181-1cf6-4cca-8462-415a5fbef465" />

## Impact
Attacker can bypass access control to view unreleased/hidden data. Depending on 
backend, could escalate to full data extraction via UNION-based injection.

## Remediation
Use parameterized queries / prepared statements instead of string concatenation.
