# Creating a UTF-8 string with accents and special characters
utf8_strings = ["café",  "cafe\u0301", "cafe\01", "cafe\00"]
def normalize_uuid(uuid: str):
    uuid_l = list(uuid)
    i = 0
    for i in range(len(uuid)):
        uuid_l[i] = uuid_l[i].upper()
        if uuid_l[i] == "-":
            uuid_l.pop(i)
            uuid_l.append(" ")

    return "".join(uuid_l)

for utf8_string in utf8_strings:
    print(utf8_string.encode(),"normalized is", normalize_uuid(utf8_string).encode())