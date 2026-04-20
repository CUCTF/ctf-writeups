# lazy-bigrams

## Summary
This challenge provides a Linux CLI program that is used to encrypt the flag by applying NATO phonetic alphabet expansion twice before performing a random bigram substitution cipher. The vulnerability in this crytographic algorithm lies in the predictable structure introduced by the double phonetic expansion, which allows the known flag prefix 'lactf{' to reveal enough bigram mappings to recover the full flag.

Artifacts:
- `chall.py`: the encryption algorithm used to generate the ciphertext.
- `ct.txt`: contains the ciphertext generated using the flag and the encryption scheme in `chall.py`
- `solve.py`: the exploit script that recovers the flag from the ciphertext provided by `ct.txt`

## Context
The `lazy_bigrams` challenge authors provides the ciphertext and the encryption scheme to generate the ciphertext from the flag.

```python
sub_bigrams = random.sample(bigrams, len(bigrams))
phonetic_map = {"A":"ALPHA","B":"BRAVO","C":"CHARLIE", ... }

def phonetic_mapping(ptext):
    cleanptext = re.sub(r'[^a-zA-Z0-9_{}]', '', ptext).upper()
    mapped = "".join([phonetic_map[c] for c in cleanptext])
    if (len(mapped) % 2 == 1):
        mapped += "X"
    return mapped

def encryption(ptext):
    cleanptext = re.sub(r'[^a-zA-Z]', '', ptext).upper()
    ctext = "".join([sub_bigrams[bigrams.index(cleanptext[i*2:(i+1)*2])] for i, _ in enumerate(cleanptext[::2])])
    return ctext

pt = phonetic_mapping(phonetic_mapping(flag))
ct = encryption(pt)
```

Looking at the `chall.py`, we can see that encryption occurs by performing `phonetic_mapping` twice on the plaintext and then using the randomly generated key `sub_bigrams` to perform a bigram substitution.

`phonetic mapping` works by converting the text to uppercase and replacing each letter with its respective NATO phonetic alphabet, specified by `phonetic_map`,and appending 'X' if the resulting text is not an even length. For example:

```
phonetic_mapping("sky") = SIERRAKIWIYANKEE
phonetic_mapping("bot") = BRAVOOSCARTANGOX
```

After this transformation occurs twice on the plaintext, we use the key `sub_bigrams`, a randomly generated permutation of `bigrams` (an array of all two letter combinations of the alphabet) to perform a bigram substitution to get the final ciphertext.

## Vulnerability
The main problem with this substitution encryption scheme is the use of `phonetic_mapping()` before the bigram substitution, which reveals a significant amount of information about the underlying plaintext bigram pairs.

Before the bigram substitution is applied, each character in the plaintext is expanded into its corresponding NATO phonetic alphabet word. The scheme applies this mapping twice, greatly increasing the length of the plaintext and producing a highly structured and predictable sequence. 

In this case, the flag format is partially known (lactf{), so expanding this prefix with phonetic_mapping() twice produces a large sequence of known plaintext characters. From this partially known plaintext, we can recover a significant amount of ciphertext-plaintext bigram mappings.

## Exploitation
By utilizing the `phonetic_mapping` function, provided from the challenge, we can perform `phonetic_mapping(phonetic_mapping("lactf{"))` to partially generate the plaintext before the bigram substitution step.

```python
def generate_known():
    bigram_map = {}
    prefix_mapping = phonetic_mapping(phonetic_mapping("lactf{"))
    for i in range(0, len(prefix_mapping), 2):
        value = prefix_mapping[i:i+2]
        if value == "OX": # We want to remove this incorrect mapping as X is added to the end of 'lactf{' phonetical mapping.
            continue
        key = line[i:i+2]
        bigram_map[key] = value
```

The key thing to note is that we need to ensure that we are removing the last bigram key-value pair as an incorrect 'X' is appended due to the result being an odd length string. However, in the real flag, the plaintext does not end at `lactf{` so this 'X' will not be here.

```
$ phonetic_mapping(phonetic_mapping("lactf{"))
LIMAINDIAMIKEALPHAALPHALIMAPAPAHOTELALPHACHARLIEHOTELALPHAROMEOLIMAINDIAECHOTANGOALPHANOVEMBERGOLFOSCARFOXTROTOSCARXRAYTANGOROMEOOSCARTANGOOSCARPAPAECHONOVEMBERCHARLIEUNIFORMROMEOLIMAYANKEEBRAVOROMEOALPHACHARLIEECHOX
```

```python
def partial_plain(bigram_map):
    final = ""
    for i in range(0, len(line), 2):
        bigram = line[i:i+2]
        if bigram not in bigram_map:
            final = final + "??"
        else:
            final += bigram_map[bigram]
    return final
```
Using the pairs we found from the flag prefix, we can iterate through ciphertext two characters at a time, recovering any plaintext that we know and adding placeholders for unknown pairs to generate a partially recovered plaintext.

From here, we can semi-bruteforce the flag by appending one letter to the flag prefix at a time and crosschecking if the double phonetic_mapping expansion aligns with the partially recovered plaintext.

```python
def double_phonetic_no_pad(text):
    p1 = phonetic_mapping(text)
    if p1.endswith("X"):
        p1 = p1[:-1]
    p2 = phonetic_mapping(p1)
    if p2.endswith("X"):
        p2 = p2[:-1]
    return p2

def check_valid(candidate, ct):
    for i in range(len(candidate)):
        if ct[i] != "?" and ct[i] != candidate[i]:
            return False
    return True

bigram_map = generate_known()
ct = partial_plain(bigram_map)
flag = "LACTF{"
chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_}"

while not flag.endswith("}"):
    for c in chars:
        temp = flag + c
        if c == "}":
            temp_ct = phonetic_mapping(phonetic_mapping(temp))
        else:
            temp_ct = double_phonetic_no_pad(temp)

        if check_valid(temp_ct, ct):
            for i in range(0, len(temp_ct), 2):
                pt_bg = temp_ct[i:i+2]
                ct_bg = line[i:i+2]
                if ct_bg not in bigram_map and len(pt_bg) == 2:
                    bigram_map[ct_bg] = pt_bg
            flag = temp
            ct = partial_plain(bigram_map)
            break
print(flag.lower())
```
Note that we once again have to remember to exclude the ending 'X' in both steps of the `phonetic_mapping()` expansion if the flag has more characters to follow, since the real flag does not end at the current prefix and any padding would produce incorrect mappings.

For each character successfully appended to the known flag text, we update the `bigram_map` with any new bigram pairs we found. Using the updated `bigram_map`, we can generate a new partial plaintext which will now contain less unknown pairs than before.

By repeating this process, we can eventually recover the full flag to solve the challenge.

## Remediation
The primary weakness of this encryption scheme is the use of `phonetic_mapping`. The double phonetic mapping expansion expands the flag into an predictable sequence and reveals a lot about the bigram pairs even from the flag prefix "lactf{" alone.

This issue can be mitigated by eliminating the phonetic mapping step entirely and directly applying the bigram substitution to the flag. Without the deterministic phonetic expansion, the plaintext would no longer contain large predictable sequences derived from the known flag prefix.

Even if an attacker could determine the bigram mappings corresponding to the prefix `("la", "ct", "f{")`, those mappings would only apply to those specific bigrams. If these bigrams do not appear again elsewhere in the flag, they would provide little useful information for recovering the remaining ciphertext. As a result, removing the phonetic expansion significantly reduces the amount of exploitable structure present in the encryption process.