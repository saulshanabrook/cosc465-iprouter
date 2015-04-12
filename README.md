cosc465-iprouter
================

Repo for projects 3-6 (or so) for COSC 465, computer networking.

```

docker build -t saulshanabrook/cosc465-iprouter-mininet -f mininet.Dockerfile .
docker run --rm -it -v $PWD:/cosc465-iprouter/ --privileged=true saulshanabrook/cosc465-iprouter-mininet
```

to create stubs for switchyard:

```
docker run --rm -it -v $PWD:/cosc465-iprouter/ -e MYPYPATH=/cosc465-iprouter/stubs/ -e PYTHONPATH=/switchyard/ --entrypoint python saulshanabrook/cosc465-iprouter -m mypy.stubgen switchyard.lib switchyard.lib.address switchyard.lib.common switchyard.lib.debug switchyard.lib.hostfirewall switchyard.lib.importcode switchyard.lib.packet switchyard.lib.packet.arp switchyard.lib.packet.common switchyard.lib.packet.dhcp switchyard.lib.packet.ethernet switchyard.lib.packet.icmp switchyard.lib.packet.icmpv6 switchyard.lib.packet.igmp switchyard.lib.packet.ipv4 switchyard.lib.packet.ipv6 switchyard.lib.packet.null switchyard.lib.packet.packet switchyard.lib.packet.ripv2 switchyard.lib.packet.tcp switchyard.lib.packet.udp switchyard.lib.packet.util switchyard.lib.pcapffi switchyard.lib.socketemu switchyard.lib.testing switchyard.lib.textcolor switchyard.lib.topo switchyard.lib.topo.topobuild switchyard.lib.topo.util switchyard.linkem switchyard.switchy_real switchyard.switchy_test switchyard.versioncheck
```


to run in test mode:

```
docker build -t saulshanabrook/cosc465-iprouter .
# testing
docker run --rm -it -v $PWD:/cosc465-iprouter/ saulshanabrook/cosc465-iprouter
# testing w/ pudb
docker run --rm -it -v $PWD:/cosc465-iprouter/ -v $PWD/.pdb:/root/.config/pudb saulshanabrook/cosc465-iprouter -v -t -d --nohandle -s routertests2.srpy myrouter.py
# testing w/ pudb launch on error
docker run --rm -it -v $PWD:/cosc465-iprouter/ -v $PWD/.pdb:/root/.config/pudb --entrypoint="python" saulshanabrook/cosc465-iprouter -m pudb.run /switchyard/srpy.py -v -t -d --nohandle -s routertests2.srpy myrouter.py
# static type check
docker run --rm -it -v $PWD:/cosc465-iprouter/ -e MYPYPATH=/cosc465-iprouter/stubs/ --entrypoint mypy saulshanabrook/cosc465-iprouter myrouter.py
```

to run in "real" mode:

```
docker build -t saulshanabrook/cosc465-iprouter-mininet -f mininet.Dockerfile .
docker run --rm -it -v $PWD:/cosc465-iprouter/ --privileged=true saulshanabrook/cosc465-iprouter-mininet

xterm router
python3 /switchyard/srpy.py myrouter -v -d

xterm client
```
