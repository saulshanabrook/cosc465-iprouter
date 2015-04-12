FROM jsommers/switchyard
RUN apt-get -y install git
RUN pip3 install git+https://github.com/JukkaL/mypy.git@91b6021d9c09b5c4c5df4aaee998115d00f3bad3 pudb

ADD . /cosc465-iprouter
WORKDIR /cosc465-iprouter
ENTRYPOINT ["python3", "/switchyard/srpy.py"]

CMD ["-v", "-t", "-d", "-s", "routertests2.srpy", "myrouter.py"]
