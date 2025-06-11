# PicoCTF: FactCheck

## Context

We are given a binary named "bin". We are given no hints.

## Exploitation

Opening the file in Ghidra, we can begin analyzing it. Let's look at the `main` function (some parts truncated for brevity):

```text
/* WARNING: Removing unreachable block (ram,0x0010170c) */

undefined8 main(void)

{
  char cVar1;
  char *pcVar2;
  long in_FS_OFFSET;
  allocator local_249;
  string local_248 [32];
  ...
  string local_48 [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  std::allocator<char>::allocator();
                    /* try { // try from 001012cf to 001012d3 has its CatchHandler @ 00101975 */
  std::string::string(local_248,"picoCTF{wELF_d0N3_mate_",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 0010130a to 0010130e has its CatchHandler @ 00101996 */
  std::string::string(local_228,"0",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 00101345 to 00101349 has its CatchHandler @ 001019b1 */
  std::string::string(local_208,"5",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 00101380 to 00101384 has its CatchHandler @ 001019cc */
  std::string::string(local_1e8,"d",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 001013bb to 001013bf has its CatchHandler @ 001019e7 */
  std::string::string(local_1c8,"3",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 001013f6 to 001013fa has its CatchHandler @ 00101a02 */
  std::string::string(local_1a8,"2",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 00101431 to 00101435 has its CatchHandler @ 00101a1d */
  std::string::string(local_188,"a",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 0010146c to 00101470 has its CatchHandler @ 00101a38 */
  std::string::string(local_168,"a",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 001014a7 to 001014ab has its CatchHandler @ 00101a53 */
  std::string::string(local_148,"e",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 001014e2 to 001014e6 has its CatchHandler @ 00101a6e */
  std::string::string(local_128,"e",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 0010151d to 00101521 has its CatchHandler @ 00101a89 */
  std::string::string(local_108,"d",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 00101558 to 0010155c has its CatchHandler @ 00101aa4 */
  std::string::string(local_e8,"b",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 00101593 to 00101597 has its CatchHandler @ 00101abf */
  std::string::string(local_c8,"e",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 001015ce to 001015d2 has its CatchHandler @ 00101ada */
  std::string::string(local_a8,"6",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 00101606 to 0010160a has its CatchHandler @ 00101af5 */
  std::string::string(local_88,"c",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 0010163e to 00101642 has its CatchHandler @ 00101b0d */
  std::string::string(local_68,"9",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                    /* try { // try from 00101676 to 0010167a has its CatchHandler @ 00101b25 */
  std::string::string(local_48,"8",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
                    /* try { // try from 00101699 to 0010185f has its CatchHandler @ 00101b3d */
  pcVar2 = (char *)std::string::operator[]((ulong)local_208);
  if (*pcVar2 < 'B') {
    std::string::operator+=(local_248,local_c8);
  }
  pcVar2 = (char *)std::string::operator[]((ulong)local_a8);
  if (*pcVar2 != 'A') {
    std::string::operator+=(local_248,local_68);
  }
  pcVar2 = (char *)std::string::operator[]((ulong)local_1c8);
  cVar1 = *pcVar2;
  pcVar2 = (char *)std::string::operator[]((ulong)local_148);
  if ((int)cVar1 - (int)*pcVar2 == 3) {
    std::string::operator+=(local_248,local_1c8);
  }
  std::string::operator+=(local_248,local_1e8);
  std::string::operator+=(local_248,local_188);
  pcVar2 = (char *)std::string::operator[]((ulong)local_168);
  if (*pcVar2 == 'G') {
    std::string::operator+=(local_248,local_168);
  }
  std::string::operator+=(local_248,local_1a8);
  std::string::operator+=(local_248,local_88);
  std::string::operator+=(local_248,local_228);
  std::string::operator+=(local_248,local_128);
  std::string::operator+=(local_248,'}');
  std::string::~string(local_48);
  ...
  std::string::~string(local_248);
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

The first thing we notice is that we are given the beginning of the flag: picoCTF{wELF_d0N3_mate_ . Let's take note of the structure of this line:

`std::string::string(local_248,"picoCTF{wELF_d0N3_mate_",&local_249);`

The variable local_248 is assigned this beginning part of the flag using the allocator local_249. Therefore, other lines with this similar structure will also be assigning values:

`std::string::string(local_228,"0",&local_249);` --> local_228 is the number 0
`std::string::string(local_188,"a",&local_249);` --> local_188 is the letter 'a'
...and so on.

Looking past these assignments, there are a number of if statements, for example:

```
pcVar2 = (char *)std::string::operator[]((ulong)local_208);
  if (*pcVar2 < 'B') {
    std::string::operator+=(local_248,local_c8);
  }
```

Above, we see that pcVar2 is assigned local_208, and earlier local_208 was assigned 5, so pcVar2 is 5. We check: if 5 < the ASCII value of B, do local_248 += local_c8. Earlier, 
we see that local_248 is the beginning part of the flag and locl_c8 is 'e'. So, we see that our flag string becomes: picoCTF{wELF_d0N3_mate_e . Therefore, we can conclude that we must go through the rest of the assignments and if statements to complete the flag! Let's go through each section:

```
pcVar2 = (char *)std::string::operator[]((ulong)local_a8);
  if (*pcVar2 != 'A') {
    std::string::operator+=(local_248,local_68);
  }
```

- pcVar2 = local_a8 = 6 local_68 = 9
- if 6 != 'A', then append local_68
- It is true that 6 != 'A' ('A' is 65)
- So append 9: picoCTF{wELF_d0N3_mate_e9

```
pcVar2 = (char *)std::string::operator[]((ulong)local_1c8);
  cVar1 = *pcVar2;
  pcVar2 = (char *)std::string::operator[]((ulong)local_148);
  if ((int)cVar1 - (int)*pcVar2 == 3) {
    std::string::operator+=(local_248,local_1c8);
  }
```

- pcVar2 = local_1c8 = 3; cVar1 = 3; pcVar2 = local_148 = e
- if (3 - 'e' == 3), append local_1c8
- This is false, so don't append.

```
std::string::operator+=(local_248,local_1e8);
  std::string::operator+=(local_248,local_188);
  pcVar2 = (char *)std::string::operator[]((ulong)local_168);
  if (*pcVar2 == 'G') {
    std::string::operator+=(local_248,local_168);
  }
```

- Append local_1e8 = d: picoCTF{wELF_d0N3_mate_e9d
- Append local_188 = a: picoCTF{wELF_d0N3_mate_e9da
- pcVar2 = local_168 = a
- if 'a' == 'G', append local_186. This is not true so don't append

```
  std::string::operator+=(local_248,local_1a8);
  std::string::operator+=(local_248,local_88);
  std::string::operator+=(local_248,local_228);
  std::string::operator+=(local_248,local_128);
  std::string::operator+=(local_248,'}');
```

- Append local_1a8 = 2
- Append local_88 = c
- Append local_228 = 0
- Append local_128 = e
- Append '}'

So our final flag is: picoCTF{wELF_d0N3_mate_e9da2c0e}

# Sources/Credits

Written by Madalina Stoicov
