# LA CTF 2024: web/la-housing-portal

## Context & Vulnerability
This is a simple housing portal that matches the user with people in the database that have the same preferences for guests, neatness, sleeptime, and wake-up time.

When clicking submit, the application creates a POST request with the information of the request, does a basic check for commenting in SQL `--` and Python `/*` before passing the arguments into a SQL instruction to search the database. The arguments are added as additional parameters for the search which returns only the ones that satisfy the conditions.

The application is not secure, as the prompt gives the warning: 
Please note, we do not condone any actual attacking of websites without permission, even if they explicitly state on their website that their systems are vulnerable.

Our goal is the flag which is in a separate table called flag under the variable name flag.

The use of SQL, the flag location, and the vulnerable website indicate that we will likely have to use SQL injection to the POST request to try to have the flag printed from that table.

## Background Information: SQL Injection (SQLi)
SQL injection is the practice of putting SQL language into inputs in order to change the backend SQL command that will be executed. This can allow the attacker to access sensitive information in the database. Common SQL injections include using `--` which is SQL language for commenting out the rest of the line, and `'1'='1'` which resolves to a true statement in SQL. 

## Exploitation
The goal is to print the flag from the flag table, but we are unable to use comments because it is being checked. We can try adding SQL injection statements to the last parameter in BurpSuite, altering the request.
A good tool for trying these requests is BurpSuite's repeater.

When trying basic SQL injection statements, we find that `'1'='1` works, and realize that there is an apostrophe at the end we must account for.

Knowing this, now we can try to use UNION to select also from the flag table. An attempt could be `' union select * from flag where '1'='1`. Note that this has to be url encoded because of the whitespaces in BurpSuite. This would not work and return a 500 error code meaning that there was a problem with the SQL injection we gave that could not be executed. This is because unioning the tables must have the same number of columns.

We may try something similar to `' union select flag, NULL, NULL, NULL, NULL from flag where '1'='1` to see how many columns and if we can get the flag, but the server returns "invalid form data" due to the injection being too long.

Using `'union select 1,2,3,4,5,6 from flag where '1` works and we see prints 2,3,4,5,6 in the columns. Then, we can add the flag to item 2 to print it out. 

`'union select 1,flag,3,4,5,6 from flag where '1`

lactf{us3_s4n1t1z3d_1npu7!!!}

## Remediation
This exploitation takes advantage of the fact that we can inject SQL code into the POST request and the input is not thoroughly checked for attacks. Some ways to prevent these attacks is encoding the information transported by the request to the server or checking the received information on the server request to verify that it is a valid option from the dropdown list before passing it into the SQL command. 

## Other Things to Note
The usage of `where '1'` actually only works in sqlite which is used for this local database because of sqlite's flexibility. This would not work in general non-sqlite cases.