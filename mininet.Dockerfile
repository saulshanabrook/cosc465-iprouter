FROM saulshanabrook/cosc465-iprouter

RUN apt-get -y install mininet xterm wireshark

ENTRYPOINT ["python"]

CMD ["start_mininet.py"]
