# PicoCTF: SQLiLite

## Summary

This challenge displays a login form with a SQL injection vulnerability. The backend uses SQLite to query user credentials, and the application exposes the SQL query it runs. This makes it easy to craft a payload. The goal is to bypass authentication and retrieve the flag using a classic SQL injection technique.

**Artifacts:**
- Web application login form (deployed on-demand container)


## Context

When the instance is launched and I navigated to the site, I was presented with a basic username and password login form. Entering random credentials (e.g., `admin` / `admin`) fails with an "Incorrect username or password" message, but crucially the page also **displays the SQL query that was executed**:

```sql
SELECT * FROM users WHERE name='admin' AND password='admin'
```

This immediately reveals:
- The database uses single quotes `'` to delimit string values
- User input is directly concatenated into the SQL query with no sanitization. This is a classic SQL injection vulnerability
- Both the `name` and `password` fields are injectable


## Vulnerability

The application constructs its SQL query by directly concatenating user-supplied input into the query string, something like:

```python
query = "SELECT * FROM users WHERE name='" + username + "' AND password='" + password + "'"
```

Because there is no input sanitization or use of parameterized queries, an attacker can inject SQL syntax through the input fields to manipulate the logic of the query.


## Exploitation

### Exploit Overview

The exploit uses SQL injection to short-circuit the authentication logic. By injecting an `OR` condition that is always true and commenting out the rest of the query, we can log in without knowing any valid credentials.

### Exploit Mitigation Considerations

- **No parameterized queries:** Input is directly concatenated into the SQL string, enabling injection.
- **SQLite comment syntax:** SQLite uses `--` (two hyphens) as the line comment character, unlike MySQL which uses `#`. This is important when crafting the payload.
- **Error visibility:** The application displays the raw SQL query on failed logins, which leaks the query structure and quote style to the attacker.

### Step-by-Step

**Step 1 — Identify the injection point**

Submit any credentials and observe the reflected SQL query. We can see single quotes wrap our input and the query uses an `AND` condition to require both username and password to match.

**Step 2 — Craft the payload**

We want to inject into the `name` field to make the `WHERE` clause always evaluate to `true`, then comment out the rest of the query (including the password check). The payload is:

```
' OR 1=1--
```

Breaking this down:
- `'` — closes the opening single quote around the username value
- `OR 1=1` — adds a condition that is always true, so the query returns a result regardless of the actual username
- `--` — SQLite's comment syntax; this comments out the rest of the query, including `AND password='...'`, effectively removing the password check entirely

**Step 3 — Submit the payload**

Enter the following in the login form:
- **Username:** `' OR 1=1--`
- **Password:** (anything, e.g. `test`)

The resulting SQL query becomes:

```sql
SELECT * FROM users WHERE name='' OR 1=1-- AND password='test'
```

Everything after `--` is treated as a comment, so the query effectively executes as:

```sql
SELECT * FROM users WHERE name='' OR 1=1
```

Since `1=1` is always true, the query returns the first user record in the database.

**Step 4 — Retrieve the flag**

The page responds with a success message. The flag is embedded in the HTML source of the page. Using **Ctrl+U** (or right-click → View Page Source) reveals:

```
Your flag is: picoCTF{L00k5_l1k3_y0u_solv3d_it_ec8a64c7}
```

---

## Why `--` and Not `#`?

A common SQL injection comment character is `#` (used in MySQL). However, this application uses **SQLite**, which does not recognize `#` as a comment. SQLite's comment syntax is `--`. Using `#` would leave a dangling quote in the query and cause a syntax error, whereas `--` cleanly terminates the query and bypasses the password check.


## Remediation

To fix this vulnerability, the application should use **parameterized queries** /prepared statements instead of string concatenation:

```python
cursor.execute("SELECT * FROM users WHERE name=? AND password=?", (username, password))
```

This would ensure that the user input is always treated as data and never as executable SQL code. Additionally, the application should **not display the raw SQL query** to the user, since this leaks implementation details that make exploitation significantly easier.

## References

- [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [SQLite comment syntax documentation](https://www.sqlite.org/lang_comment.html)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

Written by Tatyana Ilieva