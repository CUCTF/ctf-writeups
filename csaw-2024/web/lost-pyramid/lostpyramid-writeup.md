
## Context

Lost Pyramid is an interactive web site that lets users navigate through various rooms in a Pyramid in a point-and-click style. One of the rooms, the "King's lair", is not accessible, returning the error "Access Denied: King said he does not way to see you today."

The source code of the web server is given, telling us that the website is powered by flask using [jinja2](https://pypi.org/project/Jinja2/) templates. We can also see that [JSON Web Tokens (JWTs)](https://jwt.io/) are used to authenticate visitors. Specifically, every time a user visits the `/entrace` page (which every user is redirected to upon navigating to the `/` endpoint), a JWT cookie is set containing the following payload:
```
{
	"ROLE": "commoner",
	"CURRENT_DATE": (current date in D_M_YY_AD format),
	"exp": (date 3000 years from now)
}
```

The flag is rendered as part of the inaccessible `/kings_lair` page, which checks the user's token and only allows access if `ROLE` is set to `royalty` and `CURRENT_DATE` is set to the value of environment variable `KINGSDAY`. 

## Vulnerability

One major vulnerability of this web server implementation is found on the `/scarab_room` endpoint. This endpoint features a page that lets the user input a name, and then renders it as part of the response page. The issue is that instead of using jinja2 to safely place the string into the page, string concatenation is used. Additionally, all global variables are passed into the `render_template_string` function:
```return render_template_string('''
<HTML CODE>''' + name + '''<MORE HTML CODE>
''', name=name, **globals())
```

This means that we can actually inject a jinja2 expansion into the page, by inputting it into the name field. Unfortunately, we can't just dump the flag directly using this method, as some primitive validation is performed on the `name` variable. Only alphanumeric characters, curly braces, and a selection of hieroglyphs are allowed. In other words, we can dump only global variables that contain exclusively alphanumeric characters, with the curly braces letting us write out the jinja expansion syntax: `{{VARNAME}}`. This lets us retrieve the `PUBLICKEY` and `KINGSDAY` variables, but not `PRIVATE_KEY` since it contains an underscore.

Since JWTs are stored in cookies on the client-side, a cryptographic signature is added to them to ensure the server is the one that set them. This signature is then verified by the server when the JWT is read. JWTs support multiple encryption algorithms, both symmetric and asymmetric. This server uses an asymmetric EdDSA keypair, meaning the private key is used to sign and the public key is used for verification. Symmetric algorithms on the other hand use the same key to sign and verify a token. The algorithm used to sign a JWT is stored as part of its header. Ideally, the server should only accept JWTs that are signed with the algorithm it used to sign them. However, this server is configured to accept JWTs of any algorithm, as we can see from the following line:
```
decoded = jwt.decode(token, PUBLICKEY, algorithms=jwt.algorithms.get_default_algorithms())
```

This means that the server will accept a JWT encrypted using a symmetric algorithm like HS256, and verify it using the public key. The reason this is an issue is that we can retrieve the public key, and since the algorithm is symmetric, the verification will pass if the token is signed using that same public key, giving an attacker the ability to craft and sign arbitrary JWTs.

## Exploit

To obtain the flag, we begin by leaking the `PUBLICKEY` and `KINGSDAY` variables by navigating to `/scarab_room` and setting our name to `{{PUBLICKEY}}` then `{{KINGSDAY}}`.
We can then use the PyJWT library to craft our custom JWT, setting the role to `royalty`, the date to the value of the `KINGSDAY` variable we leaked, and using the public key with the `HS256` algorithm:
```
>>> payload = { 'ROLE': 'royalty', 'CURRENT_DATE': KINGSDAY, 'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=(365*3000))}
>>> token = jwt.encode(payload, key, algorithm="HS256")
>>> token
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJST0xFIjoicm95YWx0eSIsIkNVUlJFTlRfREFURSI6IktJTkdTREFZIiwiZXhwIjo5NjM0OTk3MDUxMH0.E9nWIU_ciMqIQNXYmo1dUGMNLgrgJnLvukRt4mEtAWk'
```

All we now need to do is replace the JWT in the browser's dev tools with the new value, and navigate to `/kings_lair`, which tells us the flag.

## Remediation

The first step in securing this web site is changing the `/scarab_room` endpoint to actually use jinja properly. Instead of concatenating the name with the HTML, it should be set as `{{ name }}` directly in the HTML string. Additionally, `**globals` should not be passed into the render function, as every expanded variable should be pasted in manually for better security.

The next step is to change the verification code to only accept EdDSA-signed tokens, by replacing `get_default_algorithms()` with `['EdDSA']`.