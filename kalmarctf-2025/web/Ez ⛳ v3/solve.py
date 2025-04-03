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

#!/usr/bin/env python3
