
FROM python:2

RUN apt-get update \
    && apt-get install python2.7 libpcap-dev libnet-dev -y\
    && pip install scapy impacket libpcap\
    && mkdir ./attacker\
    && cd ./attacker\
    && curl -L -o pcapy.zip https://github.com/CoreSecurity/pcapy/archive/master.zip\
    && unzip pcapy.zip\
    && cd pcapy-master\
    && python setup.py install\
    && pip install pcapy dpkt

COPY inquisitor.py /attacker/inquisitor.py

WORKDIR /attacker

CMD tail -f /dev/null