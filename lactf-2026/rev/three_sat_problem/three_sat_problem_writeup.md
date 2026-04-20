# LACTF 2026: rev/three_sat_problem

## Summary
This is a reverse engineering challenge which gives the flag if it is given an input string satisfying a 3CNF formula.

**Challenge Description**

```
I have this groundbreaking sci-fi novel idea where it's proven that P=NP then suddenly all of cryptography and subsequently all of society collapses- hey wait why are you leaving I haven't finished pitching my idea yet
```

**Artifacts**

The only file for this challenge is an ELF x64 executable, `three_sat_problem`.

**Running the Challenge**
The challenge can be run on the command line of a Linux machine and prints the following output.
```
$ ./three_sat_problem
Have you solved the Three-Sat Problem?
```

## Context
The core of this challenge is in a function which declares several thousand stack variables and computes if their assignment based on the input string satisfies a boolean expression.

This is an example of a 3SAT problem. 3SAT problems can involve any number of boolean literals, which are assembled into disjunctions of no more than three literals (hence the 3 in 3SAT). Those disjunctive clauses are put together into a CNF expression. This larger expression is said to be “satisfiable“ if there is an assignment to the literals which allows the expression to evaluate to true.

3SAT and related satisfiability problems are NP-complete. There are, however, fast exponential solvers, including the one I used, Z3.

## The Disassembly
I began by opening the binary in Ghidra. It's not packed or obfuscated, and it contains the following strings of interest.
```
Have you solved the Three-Sat Problem?
Please be serious...
I see you haven't.
Incredible! Let me get the flag for you...
```
At the top of the main method, the executable prompts the user for input.

```001010c1 48 89 df        MOV        RDI=>3sat_buf,input_ptr
001010c4 e8 97 ff        CALL       <EXTERNAL>::fgets
001010c9 48 89 df        MOV        RDI=>3sat_buf,input_ptr
001010cc 48 8d 35        LEA        RSI,[DAT_0011302b]
001010d3 e8 78 ff        CALL       <EXTERNAL>::strcspn
001010d8 48 89 df        MOV        RDI=>3sat_buf,input_ptr
001010db c6 04 03 00     MOV        byte ptr [input_ptr + input_strlen*0x1]=>3sat_
```
It checks that the input it received has the expected length of 1279, not including the null terminator.
```
001010df e8 5c ff        CALL       <EXTERNAL>::strlen
001010e4 48 3d ff        CMP        input_strlen,0x4ff                               Expects strlen of 1279

001010ea 74 09           JZ         LAB_001010f5
```
Then it loops over the input string to check that all the characters are less than 49 (ASCII 0). This tells us that the input must be a binary string. Knowing that this challenge is about satisfiability, we'll likely use that string of bits as boolean assignments.
```
001010ff 8a 03           MOV        input_strlen+0x7,byte ptr [input_ptr]=>3sat_buf
00101101 83 e8 30        SUB        input_strlen+0x4,0x30                            Subtract 48 ('0' - 0)
00101104 3c 01           CMP        input_strlen+0x7,0x1                             Compare to 1
00101106 77 e4           JA         please_be_serious                                Failure: print a        
                                                                                     message and exit
0010110b 48 39 da        CMP        RDX,input_ptr
0010110e 75 ef           JNZ        LAB_001010ff
```
It calls the 3SAT function, which checks indices of the string and returns 1 if the input characters satisfy a binary expression. It also checks that a specific value `DAT_00115352`, which is one of the bytes in the input buffer, holds a 1. This is just another constraint, so we can add it to our solver later.

```
00101112 e8 72 01        CALL       3sat_func
00101117 84 c0           TEST       3sat_ret,3sat_ret
00101119 74 09           JZ         LAB_00101124
0010111b f6 05 30        TEST       byte ptr [DAT_00115352],0x1                      754 chars into 3sat_buf
00101122 75 11           JNZ        LAB_00101135                                     Flag function
```
Finally, if the input is accepted, it is used to decode the flag from memory.
```
0010115e 48 63 14 87     MOVSXD     RDX,dword ptr [ptr_into_flag + 3sat_ret*0x4]=>   = 00000127h
00101162 89 c6           MOV        ESI,3sat_ret
00101164 89 c1           MOV        i+0x4,3sat_ret
00101166 48 ff c0        INC        j
00101169 c1 fe 03        SAR        ESI,0x3
0010116c 83 e1 07        AND        i+0x4,0x7
0010116f 8a 54 15 00     MOV        DL,byte ptr [RBP + RDX*0x1]=>DAT_00115187        RBP contains ptr to
                                                                                     input buffer
00101173 48 63 f6        MOVSXD     RSI,ESI
00101176 83 e2 01        AND        EDX,0x1
00101179 d3 e2           SHL        EDX,i+0x7
0010117b 08 54 34 07     OR         byte ptr [RSP + RSI*0x1 + 0x7],DL
0010117f 48 3d 40        CMP        j,0x140
00101185 75 d7           JNZ        LAB_0010115e
00101187 48 8d 7c        LEA        ptr_into_flag=>flag,[RSP + 0x7]
0010118c e8 9f fe        CALL       <EXTERNAL>::puts
```

## 3SAT Function
The main obstacle of this challenge is the function which checks if the binary values in the input string satisfy a 3CNF formula. This formula is the conjunction of thousands of disjunctive clauses, so it is not possible to discern the correct assignment without the use of a fast SAT solver.

```
/* Declare stack variables from the input buffer */
001013a3 88 44 24 af     MOV        byte ptr [RSP + local_444+0x3],AL
001013a7 8a 05 c4        MOV        AL,byte ptr [DAT_00115471]
001013ad f7 d0           NOT        EAX
001013af 88 04 24        MOV        byte ptr [RSP]=>local_3f0,AL
001013b2 8a 05 5e        MOV        AL,byte ptr [DAT_00115116]
001013b8 f7 d0           NOT        EAX
001013ba 83 e0 01        AND        EAX,0x1
001013bd 88 44 24 b9     MOV        byte ptr [RSP + local_438+0x1],AL
001013c1 8a 05 69        MOV        AL,byte ptr [DAT_00115330]
001013c7 f7 d0           NOT        EAX
001013c9 88 44 24 01     MOV        byte ptr [RSP + local_3ef],AL
001013cd 8a 05 00        MOV        AL,byte ptr [DAT_001150d3]

/* Combine the variables and return their result */
001128ae 8a 44 24 fa     MOV        AL,byte ptr [RSP + local_3f8+0x2]
001128b2 0a 05 a3        OR         AL,byte ptr [DAT_0011555b]
001128b8 21 f0           AND        EAX,ESI
001128ba 40 8a 74        MOV        SIL,byte ptr [RSP + local_3f8+0x3]
001128bf 40 0a 35        OR         SIL,byte ptr [DAT_001150a6]
001128c6 21 c6           AND        ESI,EAX
001128c8 8a 44 24 fb     MOV        AL,byte ptr [RSP + local_3f8+0x3]
001128cc 0a 05 a0        OR         AL,byte ptr [DAT_00115172]
```

In the original C code, this function would look something like:
```
return (input[x] ∨ ~input[y] ∨ input[z]) ∧ (~input[a] ∨ input[b] ∨ input[c]) ∧ ...
```

## Solution
I tried multiple approaches to extracting the correct assignment from the 3SAT function, first trying to lift the expression directly from both the disassembly and decompilation but facing issues with getting Angr's solver to find a satisfiable assignment. What ultimately succeeded was writing a Python [script](./working_symbolic_execution.py) to symbolically execute the function from the disassembly using Capstone. It parses instructions accessing the input buffer and constructing the clause, then uses Z3's solver to assemble the 3CNF expression. With this script, I was finally able to get the binary string and pass it into the challenge.
```
$ python3 working_symbolic_execution.py
got binary
$ cat out.txt
0111111100110101110110110000010101110011110111110000100000100011111101100111011110110100011010011001011101001001011101101110001000110011111111001000011000000101001010011100000100011110110011100111011001100011110101000111101110100000000010000011001010111011011111010000011110100010100111110000111001101100101100100000110010010001111011001010001111111001000100010010000000011111001010000000011010000011100101100000101011001010110101010001111111001011101000000001100110110010011110010011101101001100001101001110010101110010100001011011001010010101101000110101100011111111100111100111111010101000101101110101111111101010101010110001011101011111010010000010010100001100110011000111011000000111111011110111100001110011101100101000101101011110010011010011111000110110101101101111001110101001000001010110101111010011010110101000110011110100101011001110101010111101111110001011000101100101110100111111110010000110001000110100100110011110110100101011110010110111100111000001011010100100001111010100011011001101110000001111110010000111110111100110010101100000110001000010101111011010110001100011010110110000010110101000001100100000010000110111101000010001111111000101111010101110101100010111010111001010000011010101010010010100111000001100001011010001111000001111010001101101110101111011010
$ cat out.txt | ./three_sat_problem
Have you solved the Three-Sat Problem?
Incredible! Let me get the flag for you...
lactf{is_the_three_body_problem_np_hard}
```