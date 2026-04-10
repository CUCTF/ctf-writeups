# EHAX 2026: pwn/lulocator
## Context

<<<<<<< HEAD
This is a custom heap memory allocation program with a buffer overflow vulnerability and `libc` address leak.

```
Who needs that buggy malloc? Made my own completely safe lulocator.

nc chall.ehax.in 40137
```

=======
>>>>>>> 2f9cb94 (Writeup #2: EHAX pwn/lulocator)
**Artifacts**

This challenge provides four files:
- `lulocator`, an x64 ELF binary for Linux.
- `flag.txt`, which contains `EH4X{local_handout_fake_flag}`, telling us that a file of the same name exists on the challenge server.
- A copy of `libc.so.6`, which `lulocator` uses.
- A `Makefile` which builds `lulocator` on the challenge server and checks that the directory contains the executable and `libc.so.6`.

**Running the challenge**

The challenge prints the following menu in a loop.

```
$ ./lulocator
=== lulocator ===
1) new
2) write
3) delete
4) info
5) set_runner
6) run
7) quit
>
```
Each of these command options corresponds to a different `lulocator` functionality.

- `new`: create a new heap allocation of the requested size. The program keeps track of all its allocations in a pointer array, which we'll call `array_of_allocs`. If the allocation succeeds, it prints the index of that allocation.
    ```
    > 1
    size: 16
    [new] index=0
    ```
- `write`: select a valid index in the array of allocations, specify a number of bytes to write, and write to the payload of that allocation.
    ```
    > 2
    idx: 0
    len: 6
    data: hello
    [wrote]
    ```
- `delete`: free a memory allocation by index.
    ```
    > 3
    idx: 0
    [deleted]
    ```
- `info`: print the address of the allocation specified by the input index, a pointer address to `stdout` from `libc` (more on this later), and the allocation length.
    ```
    > 4
    idx: 0
    [info] addr=0x71578e77e008 out=0x71578e6045c0 len=16
    ```
- `set_runner`: set an index of the heap allocation array to run (more on this later).
    ```
    > 5
    idx: 0
    [runner set]
    ```
- `run`: run some command based on the set runner. By default, this is a print statement.
    ```
    > 6
    [mail] hello
    ```
- `quit`: self-explanatory.

## Background

**Allocation**

Decompiling the binary in Ghidra, we can see how this program implements a fairly standard function to allocate memory from an `mmap`ed heap and maintain free blocks in an explicit free list. The function, recreated here in pseudocode, will find a place to allocate the requested size plus an 8-byte header using a first-fit strategy and return a pointer to the region after the header.

```
/* called as alloc_ptr = heap_allocate(size + 0x28) */

void *heap_allocate(size_t size)
{
  
  if (size == 0)
    return 0;
  else {
    /* sizes rounded to 16-byte boundaries for alignment, min. 40 bytes */
    rounded_size = round(size + 8);
    if (rounded_size < 0x28)
      rounded_size = 0x28;

    /* iterate over blocks in the explicit free list */
    for (void *free_list_block = free_list_head; free_list_block != &free_list_head;
                                                    free_list_block = next_free_block) {
      /* get to the block header and extract its size from the upper bits */
      metadata = free_list_block - 1;
      block_size = *free_list_block & 0xfffffffffffffff0;
      if (rounded_size <= block_size) {
        /* if the remainder of the block is too small to split, allocate the whole thing */
        if (block_size - rounded_size < 0x28) {
          /* mark block as allocated */
          metadata = block_size | 1;
          remove_from_free_list(free_list_block);
        }
        /* otherwise, add the remainder to the free list */
        else {
          metadata = rounded_size | 1;
          remainder_block = rounded_size + metadata
          remainder_block_metadata = block_size - rounded_size;
          remove_from_free_list(free_list_block);
          insert_into_free_list(remainder_block);
        }
        memset(free_list_block,0,size);
        return free_list_block;
      }
    }

    /* no fit found: allocate a new block */
    if (rounded_size + heap_offset < heap_size) {
      new_block = heap_offset + heap_start;
      heap_offset += rounded_size;
      metadata = new_block - 1;
      metadata = rounded_size | 1;
      memset(new_block, 0, size);
      return new_block
    }
    else {
      print("allocator: out of memory\n");
      return 0;
    }
  }
}
```

After returning from this find-fit function, the calling function sets up pointers to the previous and next free blocks in the block. Since the block is not free, these pointers are initialized to 0. It also sets pointers to 
a function—the one we saw earlier which printed `[mail] hello`—a FILE * pointer set to `stdout`, and the allocation size. Note that this is the size the user passed, NOT the aligned block size. Finally, it adds the pointer to the array of allocations at the available index it found.

```
alloc_ptr[0] = 0;                       /* prev */
alloc_ptr[1] = 0;                       /* next */
alloc_ptr[2] = func;
alloc_ptr[3] = stdout;
alloc_ptr[4] = alloc_size;

&array_of_allocs[slot] = alloc_ptr;
printf("[new] index=%d\n", slot);
return;
```

With these two functions, we get an idea of how this program allocates blocks of memory. Here is how the example allocation of size 16 would look.

```
   0x0      0x8      0x10     0x18     0x20     0x28     0x30                             0x40
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | P  A  Y  L  O  A  D            |
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  |                                |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ ptr returned to user                       ^ where the user writes
```

**Execution**
When the user wants to delete an allocation by index, a freeing function sets the allocated metadata bit to 0 and calls a function to insert the allocation into the explicit free list (shown farther down).

To execute a function based on the selected index of the array of allocation pointers, the program calls the following function.
```
void run()
{
  if (alloc_ptr_to_runner == 0) {                   /* global variable set by set_runner */
    puts("[no runner]");
  }
  else {
    (**(code **)(alloc_ptr_to_runner + 0x10))(alloc_ptr_to_runner + 0x28);    /* function_pointer(string_payload) */
  }
  return;
}
```

## Vulnerability

The `write` function contains an improper length check, which creates an overflow vulnerability allowing the user to write past the string length allocated (CWE-119). Once the user specifies the number of bytes they'd like to write, the function does the following check, then reads the bytes directly to the memory offset of the string.
```
if (*(alloc_ptr + 0x20) + 0x18U < requested_size) {
        puts("too long");
        return;
}
printf("data: ");
read_alloc_retval = read_from_stdin(0,alloc_ptr + 0x28,requested_size);
```

The dereferenced offset gets the payload size as specified in the block information, but the code inexplicably adds `0x18` (24) bytes to this maximum size. This means that in our 16-byte allocation example, the user could write an additional 24 bytes without hitting the error message.

Because blocks are allocated contiguously, this vulnerability allows us to write up to 24 bytes into the next block, possibly overwriting the metadata, next, and previous pointers of the next block.

The second key vulnerability is the leak of a libc address to the user (CWE-200). If the user chooses the `info` option, the program prints for them by default the runtime address of `stdout`, which comes from the in-use `libc.so.6`. With one runtime address in `libc`, we can use the known offsets of the file to calculate the runtime address of any other function in the standard library, including `system`.

## Exploitation

The goal is to overwrite the `function` pointer of an allocation to the runtime address of `system` using an offset from the known `stdout` runtime address. Then we can modify the string payload of that allocation to `“/bin/sh“`, run the function, and `cat` the flag in the created shell.

**First, some dead ends**

My first thought was to allocate two contiguous blocks and directly overwrite the function pointer of the second from the first. This leverages the fact that if the size input by the user is a multiple of 16, the total block size will not require padding and the string payload of the first block will come directly before the metadata of the second. This doesn't work, however, because the user can only write a maximum of 24 bytes after the size they started with, so the next function pointer is not reachable.

Looking at what *can* be overwritten, I tried to engineer a scenario in which I overwrote the `next` and `prev` pointers of the second block, then performed some deletions and reallocations of memory blocks to set the values they pointed to—corrupted to be a function pointer—equal to the desired shell. Unfortunately, `remove_from_free_list()` contains a pointer integrity check, and `insert_into_free_list()` immediately overwrites the pointers, so there's no way to gain access through `next` and `prev`.

```
void remove_from_free_list(block_ptr)
{
  if (block_ptr == (block[0])[1]                /* block->next->prev == block */
        && (block_ptr == (block[1])[0])) {      /* block->prev->next == block */
    (block[1])[0] = block[0];                   /* block->prev->next = block->next */
    (block[0])[1] = block[1];                   /* block->next->prev = block->prev */
    return;
  } else {
    print("allocator: corrupted free list detected\n");
    exit;
  }
}

void insert_into_free_list(alloc_ptr)
{
  alloc_ptr[0] = free_list_head;        /* alloc->next = head */
  alloc_ptr[1] = &free_list_head;       /* alloc->prev = sentinel */
  free_list_head[1] = alloc_ptr;        /* head->prev = alloc */
  free_list_head = alloc_ptr;           /* head = alloc */
  return;
}
```

**What worked**

The only remaining option which is reachable by a write to the previous block and does not get overwritten or checked by a subsequent call is the metadata block at the start of each allocation, which contains a 63-bit size packed with an allocated bit. This metadata size is used only in `heap_allocate()` when looking for an existing fitting free block from the explicit free list, but its value is never checked for integrity. If we can overwrite the metadata size to be larger than the free block, then, we can force a reallocation larger than the original free block which overflows into the following block. With this overflow, we could reach the function pointer of the next block and still run it through its original pointer.

We can do this with the following steps:
1. Allocate three blocks, A, B, and C. Make them all size 16 so they do not get padded.
```
   0x0      0x8      0x10     0x18     0x20     0x28     0x30                             0x40
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ A

   0x40     0x48     0x50     0x58     0x60     0x68     0x70                             0x80
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ B

   0x80     0x88     0x90     0x98     0xa0     0xa8     0xb0                             0xc0
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ C
```
2. Record the runtime address of stdout from one of the allocations and find the address of `system`.
3. Delete allocation B, putting it on the free list.

```
   0x0      0x8      0x10     0x18     0x20     0x28     0x30                             0x40
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ A

   0x40     0x48     0x50     0x58     0x60     0x68     0x70                             0x80
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 | next = | prev = |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=0 |sentinel|sentinel|        |        |  = 16  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+

   0x80     0x88     0x90     0x98     0xa0     0xa8     0xb0                             0xc0
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ C
```

4. Write to allocation A, overflowing to make the metadata size of former allocation B larger.
```
   0x0      0x8      0x10     0x18     0x20     0x28     0x30                             0x40
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | A A A A A A A A A A A A A A A A|
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  |                                |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ A

   0x40     0x48     0x50     0x58     0x60     0x68     0x70                             0x80
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x60 | next = | prev = |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=0 |sentinel|sentinel|        |        |  = 16  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+

   0x80     0x88     0x90     0x98     0xa0     0xa8     0xb0                             0xc0
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ C
```
5. Create a new allocation D where B was using the size in the corrupted metadata. Allocation D overlaps with allocation C.
```
   0x0      0x8      0x10     0x18     0x20     0x28     0x30                             0x40
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | A A A A A A A A A A A A A A A A|
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  |                                |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ A

   0x40     0x48     0x50     0x58     0x60     0x68     0x70                             0x80
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x60 | next = | prev = |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=0 |   = 0  |   = 0  |        |        |  = 48  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ D

   0x80     0x88     0x90     0x98     0xa0     0xa8     0xb0                             0xc0
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | E  M  P  T  Y                  |
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  | P  A  Y  L  O  A  D            |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ C
```
6. Write to allocation D, overwriting the function pointer of allocation C to the runtime address of `system`.
7. Write “/bin/sh“ to C's payload.

```
   0x0      0x8      0x10     0x18     0x20     0x28     0x30                             0x40
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x40 |  next  |  prev  |  func  | stdout |  size  | A A A A A A A A A A A A A A A A|
    |alloc=1 |   = 0  |   = 0  |        |        |  = 16  |                                |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ A

   0x40     0x48     0x50     0x58     0x60     0x68     0x70                             0x80
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |sz=0x60 | next = | prev = |  func  | stdout |  size  | A A A A A A A A A A A A A A A A|
    |alloc=0 |   = 0  |   = 0  |        |        |  = 48  |                                |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ D

   0x80     0x88     0x90     0x98     0xa0     0xa8     0xb0                             0xc0
    +--------+--------+--------+--------+--------+--------+--------------------------------+
    |AAAAAAAA|AAAAAAAA|AAAAAAAA| system | stdout |  size  | “/bin/sh\00“                   |
    |        |        |        |        |        |  = 16  |                                |
    +--------+--------+--------+--------+--------+--------+--------------------------------+
             ^ C
```
8. Set the running program to C and run `system(“bin/sh“)`.

To execute these steps, I wrote a Python script, [`lulocator_exploit.py`](./lulocator_exploit.py), which connects to the challenge and handles the I/O. From this, I was able to obtain the flag.

```
$ python3 exploit4.py
[*] '/home/egk2133/lulocator'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
[*] '/home/egk2133/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to chall.ehax.in on port 40137: Done
[+] stdout leak: 0x7a9cd660d780
[+] libc base: 0x7a9cd63f2000
[+] system: 0x7a9cd6442d70
[+] A location: 0x7a9cd63af008
[+] B location: 0x7a9cd63af048
[+] C location: 0x7a9cd63af088
[+] D location: 0x7a9cd63af048
[*] Switching to interactive mode
$ /bin/cat flag.txt
EH4X{unf0rtun4t3ly_th3_lul_1s_0n_m3}
```

## Remediation

The two main vulnerabilities can be fixed as follows.
- Modify the line which allows an overflowing write to cap the number of bytes the user can write to the user-input size: `if (*(alloc_ptr + 0x20) < requested_size)` instead of `if (*(alloc_ptr + 0x20) + 0x18U < requested_size)`.
- Do not leak the runtime address of a `libc`symbol through a print statement. Better yet, do not include it in the block structure, as it's never used for any other part of the program's functionality.

There are also some larger remediations to consider.
- Implement a check of the metadata size if there's a risk of it being overwritten. This could be done by comparing the metadata size to the result of rounding the `size` field + the 8-byte metadata fied + the 40 additional bytes of pointers.
- Check that the function pointer has not been modified before running potentially user-modified code.
- Don't use custom implementations of library code; just use `malloc`!

## Credits
Written by [Elizabeth Kushelevsky](https://github.com/egkushelevsky). Challenge by `nrg` and `the_moon_guy` for EHAX CTF 2026.