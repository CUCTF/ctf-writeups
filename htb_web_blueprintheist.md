# Vulnerability Report

## Context

The vulnerable program is a Node.js Express web application for generating public planning reports as PDF files.

The application exposes a `/download` endpoint that accepts a user-supplied URL and converts the referenced page into a PDF using `wkhtmltopdf v0.12.5`.

The application also contains internal routes, including:

- `/admin`
- `/graphql`

These internal routes are protected by:

- JWT-based authentication
- An internal-only IP check requiring requests to come from `127.0.0.1`

The application uses EJS templates for rendering pages and custom error pages. Error templates are loaded from:

```text
/app/views/errors/
```

Relevant attacker-controlled inputs include:

- The URL parameter submitted to `/download`
- The JWT token supplied in the query string
- The `name` argument supplied to the GraphQL `getDataByName` query

---

## Vulnerability

### Vulnerability 1: Local File Read via `wkhtmltopdf`

The `/download` route uses outdated PDF generation software, `wkhtmltopdf v0.12.5`.

Because the application allows users to submit arbitrary URLs for PDF generation, an attacker can cause the server-side PDF renderer to fetch attacker-controlled content. Using an HTTP redirect to a `file:///` URI, the attacker can make `wkhtmltopdf` read local files from the server.

This is a combination of:

- **CWE-918: Server-Side Request Forgery**
- **CWE-22 / CWE-552: Local file disclosure**

This allows reading files such as:

```text
/etc/passwd
/app/index.js
/app/.env
```

The impact is significant because `/app/.env` contains the JWT signing secret.

---

### Vulnerability 2: JWT Secret Disclosure and Admin Token Forgery

After reading `/app/.env`, the attacker can recover the JWT signing secret.

The application trusts JWTs signed with this secret and uses the token role to determine access permissions. By creating a new JWT with:

```json
{
  "role": "admin"
}
```

the attacker can forge an admin token.

This is enabled by the previous local file read vulnerability.

---

### Vulnerability 3: Internal Route Access Through SSRF

The internal routes require the request to originate from localhost.

The check is implemented by comparing the remote address to:

```text
127.0.0.1
```

However, because `/download` causes the server to make requests on behalf of the attacker, the attacker can reach internal-only routes indirectly.

This allows access to:

```text
/graphql
/admin
```

using the server itself as the requester.

This is another SSRF impact.

---

### Vulnerability 4: SQL Injection in GraphQL `getDataByName`

The GraphQL endpoint contains a resolver named `getDataByName`.

The vulnerable query is constructed using direct string interpolation:

```js
SELECT * FROM users WHERE name like '%${args.name}%'
```

The application attempts to prevent SQL injection with this regex:

```js
const pattern = /^.*[!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]/
```

However, the regex does not properly handle newline characters. The dangerous SQL characters can be placed after a newline, bypassing the filter.

Example bypass shape:

```text
a
' OR 1=1--
```

This means the blacklist only checks the first line effectively, while the injected SQL appears after the newline.

This is:

- **CWE-89: SQL Injection**
- **CWE-184: Incomplete Blacklist**

---

### Vulnerability 5: Arbitrary File Write to EJS Error Template

Once SQL injection is available, the attacker can use database file-writing functionality to create a new file on disk.

The target file is:

```text
/app/views/errors/404.ejs
```

The application dynamically selects error templates based on HTTP status code. If a `404.ejs` template exists, the application renders it when a 404 error occurs.

The report notes that `404.ejs` does not exist by default, which makes it a valid target for file creation.

---

### Vulnerability 6: Remote Code Execution Through Malicious EJS Template

EJS templates execute server-side JavaScript.

If the attacker writes a malicious EJS payload into:

```text
/app/views/errors/404.ejs
```

then the attacker can trigger code execution by requesting a nonexistent route.

That causes the application to render the attacker-created `404.ejs` template.

This results in remote code execution.

This is:

- **CWE-94: Code Injection**
- **CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine**

---

## Exploitation

The exploit chains multiple weaknesses together.

The overall attack path is:

1. Submit an attacker-controlled URL to `/download`.
2. Use `wkhtmltopdf` redirect behavior to read local files.
3. Read `/app/.env`.
4. Extract the JWT signing secret.
5. Forge an admin JWT.
6. Use SSRF/local request behavior to access the internal `/graphql` route.
7. Exploit the newline regex bypass in `getDataByName`.
8. Use SQL injection to write a malicious EJS template to:

```text
/app/views/errors/404.ejs
```

9. Request a nonexistent route.
10. Trigger rendering of the malicious `404.ejs` template.
11. Achieve server-side code execution.

The exploit primitives are:

- Local file read
- Secret disclosure
- JWT forgery
- SSRF to localhost
- SQL injection
- Arbitrary file write
- Server-side template execution

Together, these primitives allow full remote code execution on the target application.

---

## Remediation

### Fix PDF Generation SSRF and Local File Read

Upgrade or replace `wkhtmltopdf v0.12.5`.

Additionally:

- Do not allow arbitrary user-supplied URLs.
- Use an allowlist of trusted domains.
- Block redirects to `file://`, `localhost`, `127.0.0.1`, and private IP ranges.
- Disable local file access in the PDF renderer.
- Run the PDF renderer in a sandboxed container with minimal filesystem access.

---

### Protect Secrets

The JWT signing secret should not be readable by the PDF-generation process.

Recommended changes:

- Store secrets outside the web application directory.
- Use environment variables or a secret manager.
- Apply least-privilege filesystem permissions.
- Rotate the JWT secret after compromise.

---

### Fix JWT Authorization

JWTs should remain signed with a strong secret, but access control should not rely only on client-supplied role claims.

Recommended changes:

- Validate users against server-side session or database state.
- Use short token lifetimes.
- Avoid exposing token verification errors that reveal implementation details.

---

### Fix Internal Route Protection

Do not rely only on source IP checks for internal routes.

Recommended changes:

- Require authentication and authorization even for localhost requests.
- Bind internal services to a separate private interface.
- Prevent server-side request features from accessing internal routes.
- Add SSRF protections at the network layer.

---

### Fix SQL Injection

Replace string interpolation with parameterized queries.

Vulnerable pattern:

```js
connection.query(`SELECT * FROM users WHERE name like '%${args.name}%'`)
```

Safer pattern:

```js
connection.query(
  "SELECT * FROM users WHERE name LIKE ?",
  [`%${args.name}%`]
)
```

Do not rely on blacklist regexes for SQL injection prevention.

---

### Fix Error Template Rendering

Do not dynamically render template files based on attacker-influenced values.

Recommended changes:

- Use a fixed mapping of allowed error templates.
- Do not render newly created files from writable locations.
- Ensure template directories are read-only at runtime.
- Prevent the database user from writing files to the application directory.

---

### Harden Database Permissions

The MySQL user should not have permissions that allow arbitrary file writes.

Recommended changes:

- Remove `FILE` privilege from the database user.
- Restrict `secure_file_priv`.
- Use a separate low-privilege database account for the web application.

---

### Variant Analysis

Similar vulnerabilities can be discovered by searching for:

- Server-side PDF generation using attacker-controlled URLs
- `wkhtmltopdf` usage
- `file://` access in renderers
- SQL queries built with template literals
- Blacklist-based SQL injection filters
- EJS templates stored in writable directories
- Dynamic template path construction
- Internal routes protected only by localhost checks
