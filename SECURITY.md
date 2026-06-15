# Security policy

## Vulnerability scanning

The production service at https://mitsumori-pocket.onrender.com is scanned weekly with the OWASP ZAP baseline scanner through GitHub Actions. The workflow can also be started manually after security-sensitive changes.

## Review and remediation

Scan findings are recorded in GitHub. High-risk findings are reviewed promptly, affected functionality is restricted when necessary, and fixes are deployed through the main branch. Lower-risk findings are reviewed and prioritized according to impact and exploitability.

## Application controls

- SQL statements use parameterized queries for user-controlled values.
- User-controlled text is escaped before insertion into generated HTML.
- A restrictive Content Security Policy and security response headers are applied.
- Passwords are stored using PBKDF2-HMAC-SHA256 with unique salts.
- Authentication endpoints are rate limited.
- Session tokens are random, hashed in storage, HttpOnly, SameSite, and Secure in production.
- Stripe webhook signatures and timestamps are verified before subscription status is changed.

## Reporting

Report suspected vulnerabilities privately to eksiek_t@icloud.com. Do not include customer data, passwords, payment information, or active secrets in a report.
