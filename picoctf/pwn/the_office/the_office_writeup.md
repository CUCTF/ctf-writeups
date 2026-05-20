# PicoCTF: pwn/The Office

*“I’m tired of having to secure my data on the heap, so I decided to implement my own version of malloc with canaries. It’s 10x more secure and only 100x slower!”*

## Challenge Artifacts
- `the_office`, an x86 stripped no-PIE ELF binary.

## Context
When running the challenge, we get the following menu.

```
$ nc wily-courier.picoctf.net 64845
0) Exit
1) Add employee
2) Remove employee
3) List employees
4) Get access token
```

The binary is stripped, but we can tell from the call to `__libc_start_main` that this main function starts at `0x08048e49`.

```
int main(int argc,char **argv)
{
    int employee_idx;
    int employee_arr [11];

    int option = 3; /* the first time, just print the employees */

    while (1) {
        if (option == 0) {
            return 0;
        }
    ...
    option = print_options();
    }
```

Option 1 creates a new “employee” by calling the function at `0x080488c9`. The email and building fields are optional.

```
1
Name: Elizabeth
Email (y/n)? y
Email address: egkushelevsky@gmail.com
Salary: 1000000
Phone #: 1234567890
Bldg (y/n)? y
Bldg #: 123123
```

If this is the first allocation, a call to the function at `0x08049240` will `mmap()` a heap and initialize the canary.
```
int office_init()
{   
    if (heap_listp == (void *)0x0) {
        heap_base = mmap((void *)0x0, 0x1000, 3, 0x22, -1, 0);
        if ((heap_base == (void *)0xffffffff) || (heap_base == (void *)0x0)) {
            puts("Memory Error :(");
            return 0;
        }
        else {
            /* srand(time(NULL)) */
            uint __seed = time((time_t *)0x0);
            srand(__seed);
            canary_in_mem = rand();
            heap_top = (int)heap_base + 0x1000;
            heap_listp = heap_base;
            configure_header(heap_base, 0x1000 - DAT_0804c060, 0, 0, 1);
            return 1;
        }
    }
    else
        return 1;
}
```

So, we see from the decompiled function that the canary is set using pseudorandom number generation.

There is also a call to the `configure_header()` function, which starts at `0x080491f0`. It puts the canary we just set into the start of each allocation, as well as the current and previous allocations’ size and status.

```
void configure_header(char *heap_listp, uint size, byte alloc, uint prev_size, byte prev_alloc)
{
    if (heap_base != 0) {
        *heap_base = canary_in_mem;
        heap_base[1] = alloc | size;
        heap_base[2] = prev_alloc | prev_size;
    }
    return;
}
```

This is why we see in the function that calls `office_init()` a size adjustment function which adds 12 to the block size.

```
int call_check_setup(uint requested_size)
{
    char retval;
    uint uVar1;
    uint heaplistp_param;

    if (heap_check(0) != 1) {
        puts("*** heap smashing detected ***");
        exit(-1);
    }
                        /* first call: initialize heap */
    if ((heap_listp == 0) && (retval = office_init(), retval != '\x01'))
        return 0;

                        /* max alloc: 4068 bytes */
    if (requested_size + twelve_in_data < 0xff0) {
        while (heap_listp < heap_top) {
            if ((advance_4_bytes(heap_listp) == 0) &&
              requested_size <= next_even_address(heap_listp)) {
                heap_listp = heap_base;
                adjust_heap_size(heap_listp, requested_size);

                if (heap_check(0) != 1) {
                    puts("*** heap smashing detected ***");
                    exit(-1);
                }
                return heaplistp + 0xc;
            }
            heap_listp = advance_address(heap_listp);
        }
        heap_listp = heap_base;
    }
    return 0;
}
```

This is also the first use we see of the heap check function at `0x0804981c`, which checks the header blocks and complains of heap smashing if they are incorrect. The whole implementation is not relevant here so it’s not shown, but it is worth noting that the function prints helpful information about the heap when passed a nonzero argument, which may be used for an exploit. The heap check function is called in `main()` on every prompt iteration.


Returning to the creation function, the program prompts for each part of the employee structure, reads them using `scanf()`, and writes them to the heap region.

```
char *add_employee(void)
{
    /* get pointer to space on heap (not shown) */
    char *employee_start = (char *)check_setup(0x28);

    ...
    printf("Name: ");
                                        /* "%15s" */
    __isoc99_scanf(&name_format_string, employee_start);\

    if (strncmp(employee_start,"admin", 6) == 0) {
        puts("Cannot be admin!");
        exit(-1);
    }

    printf("Email (y/n)? ");
     __isoc99_scanf("%c", &yn);

    if ((yn == 'n') || (yn == 'N')) {
        employee_start[0x10] = '\0';
        employee_start[0x11] = '\0';
        employee_start[0x12] = '\0';
        employee_start[0x13] = '\0';
    } else {
        printf("Email address: ");
        __isoc99_scanf("%127s", email);

        /* copy email onto heap */
        email_len = strnlen(email, 0x7f);
        strncpy(*(char **)(employee_start + 0x10), email, email_len);
        *(char *)(*(int *)(employee_start + 0x10) + email_len) = 0;
    }

    printf("Salary: ");
    __isoc99_scanf(&salary_format_string,employee_start + 0x14);

    printf("Phone #: ");
    __isoc99_scanf("%s",employee_start + 0x18);

    printf("Bldg (y/n)? ");
    __isoc99_scanf("%s",&yn);
    if ((yn != 'n') && (yn != 'N')) {
        printf("Bldg #: ");
        __isoc99_scanf("%u",employee_start + 0x24);

    }

    return employee_start;
}
```

From this function, we see that each employee in memory looks like this.

```
0x0                     0xc               0x1c    0x20    0x24                    0x30     0x34                     0x40
 +-----------------------+-----------------+-------+-------+-----------------------+--------+------------------------+
 | canary | curr | prev  |       name      | email | salary|         phone         |  bldg  |     unused/padding     |
 +-----------------------+-----------------+-------+-------+-----------------------+--------+------------------------+
```

The other key function of this program starts at `0x08048d42` and is called by user option 4.

```
4
Employee #?
0
Not admin
```

The function requires the username `admin`. However, as we saw in the allocation function, the user should not be able to set their name to `admin`, so the exploit will involve finding a way around this.

```
void get_flag(char *name)
{
    char flag_buf[128];

    if (strncmp(name, "admin", 6) != 0) {
        puts("Not admin");
        return;
    }

    FILE *__stream = fopen("flag.txt","r");
    fgets(flag_buf, 0x7f ,__stream);
    if (fgets(flag_buf,0x7f,__stream)) {
        puts(flag_buf);
        fclose(__stream);
        exit(0);
    }

}
```

## Vulnerability
The vulnerability is a buffer overflow in the function to allocate a new employee. The phone number is stored as a string, but the call to `scanf()` uses a format string without a length specifier (`“%s”` in `.rodata`). Without a length, we can write over the expected size into another employee’s name field.

## Exploit
We can use the pseudorandom number generation as an attack primitive to recreate the stack canary. Since it’s set by the first call to `random()` after seeding with `time(NULL)`, if we can guess the time the program runs to the granularity of 1 second, we can get the canary.

From there, we just have to allocate two blocks, free the first, and reallocate its space with an overflowed phone number to change the second name to `“admin”`. Since we know the size and allocation of both blocks, we can overwrite those as well. The phone number is a fixed 28 bytes from the end of its structure, so we fill those bytes with garbage, replace the canary, and write `“admin”`.

I accomplished these steps in [`the_office_exploit.py`](./the_office_exploit.py). I used the `ctypes` library to call the stdlib random functions directly in my Python script.

```
(venv) elizabeth@linux-vm:~/ctf$ python3 the_office_exploit.py
[*] '/home/elizabeth/ctf/the_office'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
[+] Opening connection to wily-courier.picoctf.net on port 49719: Done
[*] Canary guess: 0x3d273e5a
[*] Created first employee
[*] Created second employee
[*] Removed first employee
[+] Flag: picoCTF{54456a0651351f5815c9237f098aa558}
[*] Closed connection to wily-courier.picoctf.net port 49719
```

## Remediation
To fix this vulnerability, the program should change the `scanf()` call to use a format string which specifies a character limit. For the space shown for the phone number, this should be `"%12s"`.

It is also not a good idea to generate custom heap canaries using an easily replicable scheme. The programmer could look into a method that is harder to guess/reproduce from an attacker over a TCP connection, like how glibc stack canaries can be randomly seeded from their system’s `/dev/urandom`. In a local setting, to prevent the canary being leaked in a debugger, the programmer might change the allocation function to more frequently update the heap canaries, or look into a different protection method.

## Credits
Written by [Elizabeth Kushelevsky](https://github.com/egkushelevsky). Challenge by madStacks on PicoCTF.