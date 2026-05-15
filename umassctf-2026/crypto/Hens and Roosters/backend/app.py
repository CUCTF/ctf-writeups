import os
import string
import time
from flask import Flask, request
import redis
from uov import UOV

app = Flask(__name__)
sig_len = 508
flag = os.environ.get("FLAG", "UMASS{fakeflag}")

pool = redis.ConnectionPool(host='redis', port=6379, max_connections=50)
r = redis.Redis(connection_pool=pool)

uov = UOV()


@app.get('/buy')
def buy():
    uid = request.args.get('uid')
    if not uid:
        return f"User not specified!"
    uid = str(uid).lower()
    studs = r.get(uid)
    if studs is None:
        return f"User {uid} does not exist in our system!"
    studs = int(studs)
    payload = str(studs) + '|' + uid
    if studs == 0:
        free_sig = r.get(payload)
        if free_sig is None:
            free_sig = uov.sign(payload)
            r.set(payload, free_sig, ex=240)
            r.set(free_sig, payload, ex=240)
        else:
            free_sig = free_sig.decode()
        return f"You don't even have any studs? Save up seven studs for a lego set! Here's a free signature: {free_sig}"
    elif studs == 1:
        return "Only 1 stud? Save up 7 studs for a lego set!"
    elif studs < 7:
        return f"Only {studs} studs? Save up 7 studs for a lego set!"
    else:
        r.delete(uid)
        return f"You have 6- wait, no, 7 studs! Here's your lego set: {flag}"


@app.get('/')
def index():
    uid = os.urandom(8).hex().lower()
    r.set(uid, 0, ex=240)
    return f"Your randomly generated uid is {uid}!"


@app.post('/work')
def work():
    request_body = request.get_json()
    uid = str(request_body["uid"]).lower()
    sig = str(request_body["sig"])
    studs = r.get(uid)
    if studs is None:
        return f"User {uid} does not exist in our system!"
    studs = int(studs)
    payload = str(studs) + '|' + uid
    if len(sig) != sig_len:
        return "Incorrect signature length!"
    if not all(c in string.hexdigits for c in sig):
        return "Incorrect signature format!"
    sig_bytes = bytes.fromhex(sig)
    if not all(0 <= sig_byte < 128 for sig_byte in sig_bytes):
        return "Incorrect signature bytes!"
    value = r.get(str(sig))
    if value is None:
        r.set(sig, b'-', ex=240)
        verified = uov.verify(payload, sig_bytes)
        if verified:
            r.set(sig, payload, ex=240)
    elif value == b'-':
        return "The signature is still being processed, please send a request later!"
    else:
        verified = value.decode() == payload

    if verified:
        studs = r.incr(uid)
        if studs > 2:
            return "You're not getting any more free studs!"
        else:
            new_sig = uov.sign(str(studs) + '|' + uid)
            r.set(new_sig, str(studs) + '|' + uid, ex=240)
            return f"Your next free stud is {new_sig}!"
    else:
        return f"No free studs for faked keys!"


if __name__ == '__main__':
    app.run()
