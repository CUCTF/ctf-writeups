# Shellshock (CVE-2014–6271)

## Summary
Shellshock, also known as Backdoor, is a vulnerability in the GNU Bash shell that allows attackers to execute arbitrary commands by crafting malicious environment variables. The vulnerability arises from incorrect parsing of function definitions, which allows additional commands appended after the function body to be interpreted and executed as well.

Artifacts:
- `script.sh`: the bash script that executes commands through maliciously crafted environment variables.
- `vulnerable_bash`: the vulnerable version (4.1) of bash compiled (in x86-64) from source before the patch. Used with `script.sh` to demonstrate the vulnerability.

## Context
Bash supports exporting functions through environment variables that allows a Bash process to easily share command scripts with child bash processes. 

When a new Bash process starts, it scans environment variables matching the function defintion pattern `() { ... }` and imports the content of curly braces. 

## Vulnerability
In Bash versions up to 4.3, the main vulnerability was due to improper parsing of function definitions leading to unintended command execution.

Instead of stopping at the closing curly brace of a function definition, the `parse_and_execute` function continued parsing the entire string and treated trailing input as additional commands to execute as well.

```
int parse_and_execute(...) {
    ...
    // Continues parsing until end of input string
    while (*(bash_input.location.string)) {
        ...
        // Executes each parsed command
        last_result = execute_command_internal(command, 0, NO_PIPE, NO_PIPE, bitmap);
        ...
    }
    ...
}
```
This would result in arbitrary command execution during shell initialization, which would execute before any other user code runs.

## Exploitation
The vulnerability can be exploited by appending commands to the end of the function definition using `;` as a command separator.

Consider the following environment variable `env x1='() { :; }; echo VULNERABLE' $BASH_BIN -c 'echo Hello'`. The new Bash process would recognize this as a function definition since it contains the format `() { ... }` and try to parse it.

This would add the contents within the braces as a function. Since there are still characters left in the string, it would continue to parse and execute `echo VULNERABLE` in the new Bash process that `$BASH_BIN -c 'echo Hello'` spawned. 

Upon initialization, the new Bash shell will first print "VULNERABLE" and then process the command `echo Hello`.
```
$ env x1='() { :; }; echo VULNERABLE' ./vulnerable-bash -c 'echo Hello'
VULNERABLE
Hello
```

**Note**: Certain malformed environment variables caused Bash to crash after or instead of executing the injected command. This could trigger additional parser bugs, such as out-of-bounds access, that could lead to segmentation faults.

```
$ env x2='() { :; }; touch tmp' ./vulnerable-bash -c 'echo Test'
Segmentation fault (core dumped)
```

## Remediation
The remediation for this vulnerability was to properly handle function export parsing and command execution. 

Patched versions of Bash introduced flags `SEVAL_FUNCDEF` and `SEVAL_ONECMD` were added to resolve these vulnerabilities. 
- `SEVAL_FUNCDEF` ensured that the input only took the function definition form `() { ... }` and rejected other input formats.
- `SEVAL_ONECMD` ensured that only one command was processed, eliminating the possibility of chain commands with `;`.