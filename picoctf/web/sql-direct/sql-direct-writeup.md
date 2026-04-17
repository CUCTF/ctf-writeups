# sql-direct

## Summary

This challenge requires connecting directly to a PostgreSQL database server and using basic SQL syntax to discover and query a table containing the flag. No exploitation is needed, but the goal is to enumerate the database schema and retrieve the flag using SQL commands.

**Artifacts:**
- Remote PostgreSQL instance at `saturn.picoctf.net:55688`

---

## Context

The challenge provides a hostname, port, username (`postgres`), and password (`postgres`) to connect to a live PostgreSQL database named `pico`. PostgreSQL (also called Postgres) is an open-source relational database management system. Data is organized into **databases**, which contain **tables** comprised of **columns** and **rows**.

`psql` is the official commandline interface for interacting with PostgreSQL. It allows you to run SQL queries and psql meta-commands (prefixed with `\`) directly from the terminal.

---

## Vulnerability

 In this challenge, the database is intentionally exposed with public credentials, and the flag is stored in plaintext inside a table. The vulnerability is simply unauthenticated (or publicly credentialed) access to a database containing sensitive data.

---

## Exploitation

### Step 1 — Connect to the database

Using `psql` with the provided credentials:

```
$ psql -h saturn.picoctf.net -p 55688 -U postgres pico
Password for user postgres:
psql (18.3 (Homebrew), server 15.2 (Debian 15.2-1.pgdg110+1))
Type "help" for help.

pico=#
```

The `pico` argument specifies the database name. After entering the password `postgres`, we are dropped into an interactive psql session.

### Step 2 — Explore available psql commands

I ran `help` to show the available meta-commands:

```
pico=# help
Type:  \copyright for distribution terms
       \h for help with SQL commands
       \? for help with psql commands
       \g or terminate with semicolon to execute query
       \q to quit
```

Notably, `\?` lists all psql meta-commands. Among them:

```
\d[S+] NAME    describe table, view, sequence, or index
```

Running `\d` with no argument lists all relations (tables, views, etc.) in the current database.

### Step 3 — Enumerate the database schema

```
pico=# \d
         List of relations
 Schema | Name  | Type  |  Owner
--------+-------+-------+----------
 public | flags | table | postgres
(1 row)
```

There is one table: `flags`, owned by `postgres` in the `public` schema. This pointed to the next obvious course of action in uncovering the flag.

### Step 4 — Dump the table contents

I then used a `SELECT *` query to retrieve all rows and columns from the `flags` table:

```
pico=# select * from flags;
 id | firstname | lastname  |                address
----+-----------+-----------+----------------------------------------
  1 | Luke      | Skywalker | picoCTF{L3arN_S0m3_5qL_t0d4Y_31fd14c0}
  2 | Leia      | Organa    | Alderaan
  3 | Han       | Solo      | Corellia
(3 rows)
```

The flag is stored in the `address` column of the first row.

**Flag:** `picoCTF{L3arN_S0m3_5qL_t0d4Y_31fd14c0}`

---

## Exploit Primitives Used

- Direct connection to an exposed PostgreSQL instance using `psql`
- Database schema enumeration with `\d`
- Full table dump with `SELECT * FROM flags;`

---

## Remediation

To prevent unauthorized access to sensitive data stored in a database:

- **Do not expose database ports publicly.** The PostgreSQL port should be firewalled and only be accessible from trusted internal services.
- **Use strong, unique credentials.** Default credentials like `postgres/postgres` should not be used in any environment.
- **Apply least-privilege access controls.** Database users should only have access to the specific tables and operations they need.
- **Encrypt sensitive data at rest.** Storing flags or other sensitive values in plaintext columns means anyone with read access can retrieve them immediately.

## References

https://play.picoctf.org/practice/challenge/303?category=1&page=3
https://www.postgresql.org/docs/current/app-psql.html
https://www.postgresql.org/docs/current/information-schema.html

Written by Tatyana Ilieva 
