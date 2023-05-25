FROM lscr.io/linuxserver/wireshark:latest

RUN apk update \
    && apk add python3-dev py3-pip \
    && pip install scapy


