# UMASS CTF 2026: pwn/Factory Monitor
## Challenge Artifacts
- `factory-monitor`, an x64 unstripped PIE ELF binary.
- A `Dockerfile` to run the challenge locally. Requires the presence of a `flag.txt` file in the working directory to build.

## Context
After starting the challenge, we can get the following menu with the `help` option.

```
% docker run -p 1337:1337 --platform linux/amd64 factory-monitor &
% nc localhost 1337
Factory monitor CLI. Type 'help' for commands.
factory> help
Commands:
  help
  list
  create <name> [default_exit_code]
  deinit <id>
  start <id>
  stop <id>
  cleanup <id>
  monitor <id>
  monitor-all
  send <id> <message>
  recv <id> [timeout_ms]
  quit | exit
```

The `create()` function, reproduced below, initializes a `struct Machine` and fills it in as shown. It is assigned an ID between 0 and 31, by which the user can reference it.

```
+---------------+
| name          |   String name of the machine passed by the user.
+---------------+
| main_func     |   A pointer to the machine_main_demo() function
+---------------+
| arg           |   Return value of function, 1 by default
+---------------+
| state         |   STATE_UNUSED, STATE_INITIALIZED, STATE_RUNNING, or STATE_EXITED
+---------------+
| restart_count |   Count of how many times main_func is restarted
+---------------+
| pid           |   PID of machine process, initialized to -1
+---------------+
| pipe          |   A set of pipe file descriptors, all initialized to -1
+---------------+
```

After creating a machine, we can start running it with the `start()` function. This function forks a child process for the machine, fills in the machine‘s PID and changes its state to `STATE_RUNNING`, and sets up bidirectional communication with parent process using the pipes. Once setup is complete, the machine calls its `main_func`, which by default is the `machine_main_demo()` function reproduced below.

`machine_main_demo()` allows the factory (parent) and machine (child) to communicate. Using a custom reading function, it loops infinitely until it receives a message other than `ping`, to which it responds `pong`. Once it receives a different message, it either returns 0 if it read `exit`, returns the machine’s `arg` if it read `fail`, or else echoes that message back and loops again.

```
int machine_main_demo(Machine *machine, void *arg)
{
    size_t bytes_read;
    char msg [256];

    dprintf(machine->pipe[1], "ready:%s pid=%d\n", machine, getpid());
    while (1) {
        while (1) {
            /* Wait for message from custom reading function */
            if ((ssize_t bytes_read = read_line_fd(machine->pipe[0], msg)) < 1) {
                return 0;
            }

            if (strncmp(msg, "ping", bytes_read) != 0)
                break;
            
            /* Received “ping”: send back “pong” */
            dprintf(machine->pipe[1], "pong from %s\n", machine);
        }

        /* Handle cases where parent sent something other than “ping”
         * 1. “exit”: break, write goodbye to parent, return 0
         * 2. “fail”: write failure message to parent and return the exit code specified by arg
         * 3. Otherwise, echo the parent's message back with custom writing function and loop again
         */

        if (strncmp(msg, "exit", bytes_read) == 0)
            break;

        if (strncmp(msg, "fail", bytes_read) == 0) {
            dprintf(machine->pipe[1], "failing %s with code %d\n", machine, (ulong)arg & 0xffffffff);
            return (int)arg;
        }

        dprintf(machine->pipe[1], "echo[%s]: \n", machine);
        write_all(machine->pipe[1], msg, bytes_read);
        write_all(machine->pipe[1], "\n",1);
    }

    dprintf(machine->pipe[1], "bye from %s\n", machine);
    return 0;
}
```

The user can call the `cli_recv()` and `cli_send()` functions to interface with the machine as the parent.

`factory-monitor` also provides a function which the parent can call to “monitor” one of its running machines.

```
int machine_monitor(Machine *machine)
{
    int ret;
    int status_code;
    pid_t result;
    
    if (machine->state == STATE_RUNNING) {
        int status;
        waitpid(machine->pid, &status, 1);
        /* omitting waitpid error checking */

        machine->state = STATE_EXITED;

        /* exit status 0 */
        if ((status & 0x7f) == 0) {
            status_code = status >> 8 & 0xff;
            if (status_code == 0) {
                printf("[INFO] Machine \'%s\' (PID %d) exited successfully\n", machine, machine->pid);
                return 0;
            }
            printf("[WARN] Machine \'%s\' (PID %d) exited with status %d. Restarting...\n",machine,
                  (ulong)(uint)machine->pid,(ulong)(status >> 8 & 0xff));
        }

        /* exit status greater than 0 */
        else if ((char) ( ( (byte)status & 0x7f) + 1) >> 1 < 1) {
            printf("[WARN] Machine \'%s\' (PID %d) exited with unknown status. Restarting...\n",machine,
                  machine->pid);
        } else {
            printf("[WARN] Machine \'%s\' (PID %d) was killed by signal %d. Restarting...\n", machine,
                  machine->pid, (status & 0x7f));
        }

        machine_cleanup(machine);
        machine->restart_count++;
        ret = machine_start(machine);
        if (ret < 0) {
            printf("[ERROR] Failed to restart machine \'%s\'\n",machine);
            return -1;
          }
          else {
            return 0;
          }
      }
    printf("[ERROR] Machine \'%s\' is not in running state (current state: %d)\n",machine,
            (ulong)machine->state);
    return -1;
}
```

There are two key insights from this function.
- If a machine exits with any status other than 0, it will be restarted.
- Even if a machine is cleaned up, it is not deinitialized; that is done by the `machine_deinit()` function, accessible from the user menu. When a machine exits on any status, it may be rerun without reinitialization.

The remainder of user options are straightforward and not relevant to the exploit.

## Vulnerability
The custom function this program uses to read a message from a pipe does not check the size of the buffer to which it writes and is vulnerable to a buffer overflow. It simply reads one byte at a time from the pipe, then puts the byte at an offset from the start of the passed buffer and increments that offset in a loop.

```
int read_line_fd(int fd, char *out)
{
    char c;
    ssize_t n;
    size_t pos = 0;

    while (n = read(fd, &c, 1), n != 0) {
        if (n < 0) {
          if (errno == EINTR)
              return -1;
        }
        else {
          if (c == '\n')
              return pos;
          out[pos] = c;
          pos++;
        }
    }
}
```

This function is called by both the parent (in `cli_recv()`) and the child (in `machine_main_demo()`).

## Exploit
The buffer passed to `read_line_fd()` from the machine is stack allocated in `machine_main_demo()`, so we can deterministically write past it to reach the return address saved on the stack and overwrite whither we return.

Since our ultimate goal is to get the flag from the `flag.txt` file, we must find a sequence of commands to open the file, read its contents, and print the flag. We can see from the symbol table that the `open()` function is imported at offset `0x38a40` from the start of the executable, and we have the option of `read()` or `read_line_fd()` to read the flag (entries highlighted in symbol table shown below).

![Symbol table](./symbol-table.png)

Because the program’s stack is not executable (seen through `readelf -l`), we cannot directly execute shellcode to run these functions. Instead, we can use existing instruction sequences from the programmer’s `.text` section, which is executable, to build an ROP chain and execute our own commands.

The binary has sequences to pop a value into `rdi` at `0xc028` (`5f 5d c3`) and into `rsi` at `0x15bc7` (`5e 5d c3`). However, there is no gadget which would give us `rdx` (`5a 5d c3`), which prevents us from calling a function that needs `rdx` to pass a third argument. This means that instead of calling `read`, we must use the `read_line_fd()`, which only takes two arguments: the input stream and the buffer. We will also use a `ret` instruction from `0xa382` to align the stack before calling our functions.

The reading function we are using takes a file descriptor as its first argument, so we choose to send our message from the terminal as the parent and read from the child’s pipe. We see in the `machine_start()` function that this set of pipes is created first, so we can guess the read end will have FD 3. We first have to write the filepath to memory, then open it, then read the file from the opened FD into a memory region, then print it. For simplicity and availability, we will do this print with `puts()`, found at offset `0x15fc0`.

We can write the filename and flag contents into two “buffers” in the `.bss` section, which has write permissions. The only requirements are that these regions do not contain `\n` characters, as these would cause `read_line_fd()` to stop reading prematurely.

Here is a more comprehensive overview of the ROP chain we assemble.
```
Read filepath from pipe: read_line_fd(CHILD_FD, filename_region)
-----------------------------------------------------------------------
|PIE base + 0xc028: the gadget to pop the first argument into rdi      |
|3: the child file descriptor, which will go into rdi                  |
|0: to align instruction                                               |
|                                                                      |
|PIE base + 0x15bc7: the gadget to pop the second argument into rsi    |
|<address>: the region found in the .bss section to write the filename |
|0: to align instruction                                               |
|                                                                      |
|PIE base + 0x9f9f: the read_line_fd function to call                  |
-----------------------------------------------------------------------

Open the flag file for reading: open(filename_region, 0)
-----------------------------------------------------------------------
|PIE base + 0xc028: the gadget to pop the first argument into rdi      |
|<address>: the region found in the .bss section to write the filename |
|0: to align instruction                                               |
|                                                                      |
|PIE base + 0x15bc7: the gadget to pop the second argument into rsi    |
|<address>: null flags argument put into rsi                           |
|0: to align instruction                                               |
|                                                                      |
|PIE base + 0x38a40: the open function to call                         |
-----------------------------------------------------------------------

Read flag from file: read_line_fd(FLAG_FD, flag_region)
-----------------------------------------------------------------------
|PIE base + 0xc028: the gadget to pop the first argument into rdi      |
|3: the flag file descriptor, which will go into rdi                   |
|0: to align instruction                                               |
|                                                                      |
|PIE base + 0x15bc7: the gadget to pop the second argument into rsi    |
|<address>: the region found in the .bss section to write the flag     |
|0: to align instruction                                               |
|                                                                      |
|PIE base + 0x9f9f: the read_line_fd function to call                  |
-----------------------------------------------------------------------

Print the flag: puts(flag_region)
-----------------------------------------------------------------------
|PIE base + 0xa382: the ret gadget to align the call                   |
|                                                                      |
|PIE base + 0xc028: the gadget to pop the first argument into rdi      |
|3: the flag file descriptor, which will go into rdi                   |
|0: to align instruction                                               |
|                                                                      |
|PIE base + 0x15fc0: the puts function to call                         |
-----------------------------------------------------------------------
```

The only remaining obstacle is to find the runtime addresses of all these functions by leaking the PIE base of the program. This can be done with the functionality described in `machine_monitor()`. The monitoring function only reports success if the machine exited with status 0, so if we find an `exit` instruction in the disassembly, we can brute-force guess its runtime address until we get a successful exit. Otherwise, the machine will be restarted by `machine_monitor()` and we can guess again. Such an `exit` instruction is found at `0x10b459`.

With these factors, we can solve the challenge using a script with the following steps.

1. Create and start a machine with monitoring.
2. Find the runtime address of the `exit` instruction and use it to calculate the PIE base.
3. Find regions in `.bss` to write the flag and filename.
4. Build the ROP chain with the known runtime addresses of the necessary instructions and functions.
5. Send a command from the parent to execute the ROP chain and get the flag.

The attached script, [`exploit.py`](./exploit.py), gets the flag:
```
UMASS{AsLR_L3Ak}
```

## Remediation
The vulnerability for this challenge could be resolved by switching to a reading function with a parameter of maximum number of bytes to read. Since this program expects communications to be newline-terminated, `fgets()` would be a good choice.

## Reflection
This was my first exploit using a ROP chain. It was definitely a learning curve, but I definitely understand it well now and will have that skill going forward. This challenge was a useful learning environment for such a skill as I had to understand every step that came before and after the ROP chain.

## Credits
Written by [Elizabeth Kushelevsky](https://github.com/egkushelevsky).