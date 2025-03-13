
## Context

*MC Flag Checker* is a reversing challenge that takes the form of a [Minecraft datapack](https://minecraft.wiki/w/Data_pack) with the role of checking if a certain flag is correct or not. The pack can be installed into a game save and run with the `/function chall:check_flag` command.

Minecraft datapacks allow players to extend the game's core mechanics with custom resources and logic without directly modifying the game's code. They usually contain asset files like textures and sounds as well as `.mcfunction` files which are just a set of in-game commands that are run sequentially when the function is invoked. Although mcfunction files look like code, their purely procedural nature and reliance on in-game commands means implementing basic routines like conditions and loops can be very cumbersome.

## Initial observations

Upon first running the function, nothing seems to be happening. The function doesn't even take any input, meaning the first challenge is to figure out how to pass the flag we want to check to the function.

Looking at the provided archive's directory structure, we can see that the pack is primarily composed of the previously mentioned `.mcfunction` files:

```
data
├── chall
│   └── functions
│       ├── check_flag.mcfunction
│       ├── f1.mcfunction
│       ├── f2.mcfunction
│       ├── f3.mcfunction
│       ├── f4.mcfunction
│       ├── f5.mcfunction
│       ├── f6.mcfunction
│       ├── line007
│       │   └── while1.mcfunction
│       ├── line019
│       │   └── execute2.mcfunction
│       ├── line028
│       │   ├── else4.mcfunction
│       │   ├── else5.mcfunction
│       │   └── execute3.mcfunction
│       ├── line049
│       │   └── for006.mcfunction
│       ├── line1771
│       │   └── execute7.mcfunction
│       └── reset.mcfunction
└── minecraft
    └── tags
        └── functions
            ├── load.json
            └── tick.json
```

The names of some of these files (`else4.mcfunction`, `for006.mcfunction`, `while1.mcfunction`, ...) suggest that this pack was initially written in a more standard programming language with proper flow control functionality, and transpiled into mcfunction code. The two `.json` files act as hooks to tell the game what functions to run when the datapack is loaded and every time the game "ticks" (every 20th of a second assuming no lag). `tick.json` is empty, and `load.json` triggers the pack's `reset` function.

Two file names stand out: `check_flag.mcfunction` and `reset.mcfunction`. The former appears to be the entry point of the flag checking logic, whereas the latter seems to be preparing the state required to run this logic. Both files make extensive use of the `scoreboard` command, a Minecraft command that was introduced to let players track certain stats like number of in-game deaths or kills on multiplayer servers, but has also become very popular for map makers and datapack authors as it can be used to store, check, and operate on integer values similarly to variables in a traditional programming language. `reset.mcfunction` also uses the `fill` and `data` commands to place stone items with custom metadata into a grid of jukebox blocks located at the origin of the world.

Hoping back in game and teleporting to the origin using `/tp 0 0 0`, we can see that the jukeboxes are indeed present and do in fact contain stone items. (Note that jukebox blocks are intended to only contain music disc items but any item can be inserted into them with the help of commands). I initially theorized that these jukeboxes could be used to somehow input the flag that should be checked, but their great number (40 * 40 = 1600) compared to the expected length of a CTF flag as well as the fact that they came pre-filled with data made this unlikely. 

Both `reset` and `check_flag` also contain multiple mentions of scoreboard objectives named `RegN`, `N` being an integer from 0 to 255. Interestingly, `reset` initializes them to 0, and `check_flag` manipulates them in various ways before comparing the first 40 to hard-coded integers. If all 40 comparisons pass, a `give` command is executed to give the player 4 diamonds. This makes these `Reg` scoreboard objectives a good candidate for our flag input. I concluded that the goal of this challenge was to reverse engineer the logic that manipulates these "registers" between their initialization and the final check, to somehow find the right initial values that will make them equal to the hard-coded integers at the time of the comparison.

## Reverse-engineering Minecraft function code

As stated earlier, `mcfunction` files lack many features you would expect in any programming language. There are no if statements, no while or for loops, and there isn't even a clear concept of "variables" as we know them. Function calls sort of exist, but there is no concept of scope, and you can't directly pass parameters into functions or return values from them. Datapacks get around this by hijacking certain game mechanics to re-implement these essential features. As briefly mentioned earlier, scoreboard objectives can be used as variables, though they can only be of type integer. Function parameters and return values can be implemented simply by reserving certain scoreboard objectives for this purpose, similarly to how they are implemented in assembly. Loops can be implemented by just calling a function within itself and if statements can be implemented with the help of the `execute` command that lets players run a command only if a certain condition is met.

Let's look at an example:
```
scoreboard players operation Global Param0 = Global var2
scoreboard players operation Global Param1 = Global var1
function chall:f1
scoreboard players operation Global var3 = Global ReturnValue
scoreboard players operation Global Reg0 = Global var3
```

The first line sets the value of the scoreboard objective `Param0`for player `Global` to that players value on objective `var2`, which basically means it sets the variable `Param0` to `var2`. The next line sets `Param1` to to `var1`. The commands contained in `f1.mcfunction` are then executed, after which `var3` is set to `ReturnValue` (presumably set by `f1`) and `Reg0` is set to `var3`.

In pseudocode, this snippet could look like this:
```
var3 = f1(var2, var1)
Reg0 = var3
```

As we can see, the downside of having to use these "hacks" to implement essential coding routines is that they make the code hard to read, and really long! The lack of arrays and for loops means code repetition is very common. This is why datapack authors often rely on automated tools to convert intermediate, more "high-level" code into mcfunction code, which makes development much easier. As hinted at earlier, this is probably also the case here. This could be the reason why the code is very monolithic, hard to read, full of non-descriptive variable names and without any form of comments. On the flip side, it also means the program is built with clear, repeatable patterns that are often indicative of the code that was used to generate them. This gave me the idea of writing a simple decompiler to convert the hard-to-read mcfunction code into Python code.

## Decompiling mcfunction code

To simplify the code, I wrote a simple Python script that replaces certain commonly used commands with equivalent Python code. For example, `scoreboard players operation` could easily be replaced by a simple assignment and/or operation depending on the arguments of the command. 

A strange quirk about the code I discovered was that variables and constants used the scoreboard differently. Variables were replaced by objectives named like them, and their value was stored as the score of the player named "Global". Constants however were all stored on one scoreboard objective named "Constant", and individual constant values were different players' score for that objective. Additionally, since mcfunction code doesn't have scope, I had the script convert variable references to references to certain keys in three global dictionaries (`Constant`, `Global`, `Storage`), so I didn't have to use Python's global keyword for every single variable in every single function. `Constant` was for global constants, `Global` for variables, and `Storage` for data stored in the jukeboxes. 

I had the script convert every mcfunction file to Python first, then link them together into one script. The aim was to produce correct Python code that could be executed as is to simulate the datapack's logic.

Here is a snippet from the generated Python file:

```
def check_flag():
    Global['var1'] = 106
    Global['Param0'] = Global['var1']
    f4()
    Global['var1'] = Global['ReturnValue']
    Global['var2'] = Global['Reg0']
    Global['Param0'] = Global['var2']
    Global['Param1'] = Global['var1']
    f1()
    Global['var3'] = Global['ReturnValue']
    Global['Reg0'] = Global['var3']
    Global['Param0'] = Global['var1']
    f4()
    Global['var1'] = Global['ReturnValue']
    Global['var2'] = Global['Reg1']
    Global['Param0'] = Global['var2']
    Global['Param1'] = Global['var1']
    f1()
    Global['var3'] = Global['ReturnValue']
    Global['Reg1'] = Global['var3']
```
*The [full decompilation](decompiled.py) and [decompiler code](decompiler.py) are provided with this write-up.*

This was still ugly, but at least now I could see what was happening without having to refer to the [Minecraft wiki](https://minecraft.wiki/w/Commands) every 5 seconds. I then spend a lot of time going through every function, from the shortest to the longest to understand what each did and rewrite it in more standard Python code. Let's look at an example:

```
def f3():
    Global['y'] = Global['Param1']
    Global['x'] = Global['Param0']
    Global['f3_scratch0'] = 1
    if Global['x'] > Global['y']: line019_execute2()
    if Global['f3_scratch0'] >= 1: Global['ReturnValue'] = Global['y']

def line019_execute2():
    Global['ReturnValue'] = Global['x']
    Global['f3_scratch0'] = 0
```

Without understanding what these functions do, we can move the parameters into the function signature, add a return statement, inline the function `line019_execute2` and replace the `Global` dictionary with function-local variables, giving us the following code:

```
def f3(x, y):
	scratch0 = 1
    if x > y:
	    return x
	    scratch0 = 0
    if scratch0 >= 1:
	    return y
```

Simplifying this, we get:

```
def f3(x, y):
    if x > y:
	    return x
	else:
	    return y
```

Which is just a `max` function. We can now simplify all calls to `f3`, replacing them with calls to `max`, and repeat this for other functions.

In the end, we are left with 5 functions:
* `f1`, which takes two integers and returns a sum of mathematical operations performed on its parameters in a loop
* `f5`, which performs [modular exponentiation](https://en.wikipedia.org/wiki/Modular_exponentiation)
* `f6`, which performs modular matrix multiplication, multiplying the values stored in the jukeboxes (the matrix) by the first 40 registers (the vector) modulo 251
* `check_flag`, which performs 4 steps:
	1. Registers 0-39 are altered using `f1` and a secondary variable that is changed between every register
	2. Registers 0-39 are replaced with the modular exponentiation of 6 to the power of the register's current value, modulo 251.
	3. Registers 0-39 are replaced by the result of `f6`
	4. Registers 0-39 are compared to 40 hard coded integers. If they all match, the player is given 4 diamonds and the message "You get 4 diamond" is send to all players on the server
* `reset`, which sets all registers to 0 and sets the jukebox data

## Recovering the original registers

To find the correct initial register values, we need to reverse the steps performed by `check_flag`, to go from the expected values to the initial values. This is easy to do for steps 1 and 2 as they are performed on a per-register basis and can therefore be bruteforced in a short time, but step 3 (`f6`) cannot be bruteforced in reasonable time as all 40 registers are used to get each register's new value.

Luckily, after reviewing some linear algebra, I discovered that the operation can be reversed mathematically if the matrix is invertible modulo 251. After a few unsuccessful attempts using NumPy, my favorite LLM-based chat application was able to assist me in writing [working code](matrix_math.py) to reverse the modular matrix multiplication.

I'm sure there also exists some elegant mathematical way to reverse steps 1 and 2, but at this point it was getting late and I really wanted to see something that looked like a flag. Thus, I wrote a simple bruteforcer that tried every positive integer for each register, then performed steps 1 and 2 on it until the result matched the number obtained for that register by inverted matrix multiplication. The final array of registers could then be converted into text using ASCII decoding.

*The complete solution script is available [here](solution.py).*

## Finding the flag

After putting it all together, I ran my completed solution script. Keep in mind that at this point, I had no confirmation that my assumption about registers being the flag input was correct. I also didn't know if my reverse engineered code had diverged from what the original datapack was doing in even the slightest of ways which would totally ruin the result. Even the assumption that the flag was ASCII-encoded could have been wrong. Yet, against all odds, I was ecstatic to see the following text print in my terminal:

```
lactf{y4Y_th1s_fl4g_g1v3s_y0u_4_d14m0nd}
['give', '@s', 'minecraft:diamond', '4']
['say', '"You', 'get', '4', 'diamond"']
```

Seeing that flag after hours of reverse engineering really did feel like getting 4 diamond :)

## Final thoughts

I decided to start working on this challenge because I had done a lot of "programming" with Minecraft commands when I was younger, so I thought this one was perfect for me. It also seemed like a fun, unique challenge to distract me from all the binary exploitation and cross-site-scripting I had done until then. I did not expected this to turn into such a rabbit hole, and sunk cost fallacy really helped me persevere. In the end, I learned some things about Minecraft, I learned some things about Linear Algebra, and I got to write a basic decompiler for the first time in my life! I really did not expect that to happen during a CTF competition. Most importantly, I had a ton of fun, and I am extremely happy to have made it to the end of this very interesting challenge!