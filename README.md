#ssdp-fake

Spoof SSDP announcements for devices off-lan

This is a quick hack to send out SSDP announcements for devices which are not on the LAN.
Currently it is very hacky, and it only works for Media Servers.

This allows access to media servers which are not on the same LAN, as long as they are
accessible by both UDP and TCP.

It works by sending a unicast request to the server (you have to know the IP address of
the server), picking the URL from the response, and then sending out local multicast
announcements for the server.  It is very simple: it sends roku specific multicast
announcements periodically, and it sends all the responses whenever it sees a search.

Note: all this handles is the discovery.  The client then uses the URL to contact the 
server directly.

## Versions

There are only python version, it was updated to work with Python3.

This repo is a fork where the perl version was removed, if you need
the perl one, please go to https://github.com/GrahamCobb/ssdp-fake


## Usage

``` python
ssdp-fake.py --help

ssdp-fake.py --listen-only

ssdp-fake.py --all [--interval=N] server.ip.address
```

`--all` is recommended. Leaving it out is supposed to confine the announcements to the loopback
interface so only clients on the same host will see the server, but it doesn't work properly.

## TODO

### Multiple servers
It would be nice to be able to list multiple servers and have them all announced.
At the moment, the code only handles a single server but it is possible to run multiple copies
on the same system to announce for multiple servers.

### Different types of servers
At the moment the announcements bear little relationship to what the server is actually offering:
they always offer a Media Server. It would be nice to actually parse the response from the server and
set the correct announcements.

## Real Solution
The real solution to this problem, would be a real SSDP proxy, which would collect
announcements from one LAN, forward them to a program on another LAN which would manage
the announcements on that LAN.  Apparently this is harder than it seems, because
I am aware that this has been looked into but I don't know of any solutions.

This solution also has the advantage that it doesn't require anything running on the remote
LAN, as long as the remote device address is known.

## Credits
This code was forked from this repo: https://github.com/GrahamCobb/ssdp-fake

Python multicast code taken from Stack Overflow (https://stackoverflow.com/questions/603852/multicast-in-python/1794373#1794373) by tolomea (https://stackoverflow.com/users/10471/tolomea)

Other example code taken from Stack Overflow by Toddeman, however it does not seem to be available any longer

## Notices
Copyright (c) 2022 Rafael Alpízar L.

This software is distributed under the GPL (see the copyright notices and the LICENSE file).

`ssdp-fake.py` is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

`ssdp-fake.py` is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
