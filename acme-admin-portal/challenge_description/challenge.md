# ACME Internal Admin Portal

**Category:** Web Exploitation  
**Difficulty:** Easy  
**Points:** 100  

---

## Scenario

Our threat intelligence team has flagged an internal IT administration portal belonging to ACME Technologies that appears to have been accidentally exposed to the public internet.

The portal contains several network diagnostic utilities used by their operations staff. Something about the way these tools are implemented doesn't seem quite right.

Can you investigate the portal and retrieve the hidden flag?

---

## Target

```
http://localhost:5000
```

*(If deployed remotely, your instructor will provide the target URL.)*

---

## Objective

Find and exploit the vulnerability to retrieve the flag.

Flags are in the format:

```
flag{...}
```

---

## Hints

<details>
<summary>Hint 1 — Where to look</summary>
Focus on the Network Tools page. Only one utility is actually functional.
</details>

<details>
<summary>Hint 2 — What to look for</summary>
The ping tool takes user input and appears to execute a real system command. What happens when you give it something unexpected?
</details>

<details>
<summary>Hint 3 — How to exploit</summary>
Try using shell metacharacters in the input field. What does a semicolon (;) do in a shell?
</details>

---

## Deployment

See `DEPLOY.md` for setup instructions.

---

*This challenge was created for educational purposes as part of an independent study cybersecurity course.*
