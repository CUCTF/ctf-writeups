FROM ubuntu:24.04@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab

RUN apt update && apt install -y socat

RUN groupadd -g 993 kvm && useradd -G kvm ctf

COPY lkvm-static run.sh bzImage initramfs.cpio.gz .
RUN echo "kalmar{redacted}" > /flag-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32).txt

USER ctf
ENV HOME=/tmp

EXPOSE 1337

CMD socat tcp-l:1337,reuseaddr,fork exec:/run.sh,pty,echo=0,raw,iexten=0
