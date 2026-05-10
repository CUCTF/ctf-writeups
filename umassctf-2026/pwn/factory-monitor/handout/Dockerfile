# Build
FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y \
        socat


RUN useradd -m -s /bin/bash ctf

WORKDIR /ctf

COPY factory-monitor .
COPY flag.txt .

RUN chmod 555 /ctf/factory-monitor && \
    chmod 444 /ctf/flag.txt && \
    chown -R root:root /ctf

USER ctf
WORKDIR /home/ctf

EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/ctf/factory-monitor,stderr"]