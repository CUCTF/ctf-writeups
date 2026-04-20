from collections import defaultdict
import re

phonetic_map = {"A":"ALPHA","B":"BRAVO","C":"CHARLIE","D":"DELTA","E":"ECHO","F":"FOXTROT","G":"GOLF","H":"HOTEL","I":"INDIA","J":"JULIETT","K":"KILO","L":"LIMA","M":"MIKE","N":"NOVEMBER","O":"OSCAR","P":"PAPA","Q":"QUEBEC","R":"ROMEO","S":"SIERRA","T":"TANGO","U":"UNIFORM","V":"VICTOR","W":"WHISKEY","X":"XRAY","Y":"YANKEE","Z":"ZULU","_":"UNDERSCORE","{":"OPENCURLYBRACE","}":"CLOSECURLYBRACE","0":"ZERO","1":"ONE","2":"TWO","3":"THREE","4":"FOUR","5":"FIVE","6":"SIX","7":"SEVEN","8":"EIGHT","9":"NINE"}
f = open("./ct.txt")
line = f.readline()
dict = defaultdict(int)

def phonetic_mapping(ptext):
    cleanptext = re.sub(r'[^a-zA-Z0-9_{}]', '', ptext).upper()
    mapped = "".join([phonetic_map[c] for c in cleanptext])
    if (len(mapped) % 2 == 1):
        mapped += "X"
    return mapped

def double_phonetic_no_pad(text):
    p1 = phonetic_mapping(text)
    if p1.endswith("X"):
        p1 = p1[:-1]
    p2 = phonetic_mapping(p1)
    if p2.endswith("X"):
        p2 = p2[:-1]
    return p2

def generate_known():
    bigram_map = {}
    prefix_mapping = phonetic_mapping(phonetic_mapping("lactf{"))
    for i in range(0, len(prefix_mapping), 2):
        value = prefix_mapping[i:i+2]
        if value == "OX": # We want to remove this incorrect mapping as X is added to the end of 'lactf{' phonetical mapping.
            continue
        key = line[i:i+2]
        bigram_map[key] = value
    print(len(bigram_map))
    return bigram_map

def partial_plain(bigram_map):
    final = ""
    for i in range(0, len(line), 2):
        bigram = line[i:i+2]
        if bigram not in bigram_map:
            final = final + "??"
        else:
            final += bigram_map[bigram]
    return final

def check_valid(candidate, ct):
    for i in range(len(candidate)):
        if ct[i] != "?" and ct[i] != candidate[i]:
            return False
    return True

if __name__ == "__main__":
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
            