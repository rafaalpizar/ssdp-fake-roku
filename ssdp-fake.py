#!/usr/bin/python3
# Copyright (C) 2014 Graham R. Cobb
# Released under GPL V2 -- see LICENSE
# Python multicast code taken from Stack Overflow (https://stackoverflow.com/questions/603852/multicast-in-python/1794373#1794373) by tolomea (https://stackoverflow.com/users/10471/tolomea) under CC BY-SA 3.0
# Other example code taken from Stack Overflow by Toddeman (under CC BY-SA 3.0), however it does not seem to be available any longer

# Refactor to python3 by Rafael Alpízar

import socket
import struct
import time
import select
import re
import logging
from optparse import OptionParser

VERSION='0.5'

DLNA_GRP = '239.255.255.250'
DLNA_PORT = 1900
MCAST_IF = '127.0.0.1'

CRLF = "\015\012"

#SERVER='192.168.0.238'
SERVER=''
UUID=''
URL=''
INTERVAL = 180


logging.basicConfig(level=logging.DEBUG)


parser = OptionParser(usage="usage: %prog [options] server\n       %prog --listen-only",
	epilog="Server can be specified as hostname or IP address and should be omitted if --listen-only is used",
	version="%prog "+VERSION)
parser.add_option("-t", "--localhost",
                  action="store_true", dest="localh", default=False,
                  help="send announcements only on loopback interface")
parser.add_option("-i", "--interval", type="int", dest="interval", default=INTERVAL,
		  help="seconds between notification updates (default %default)")
parser.add_option("-s", "--sourceip", type="str", dest="sourceip", default="",
		  help="use this source IP to send SSDP announcements (if not set all interfaces will be used")
parser.add_option("-l", "--listen-only",
                  action="store_true", dest="listen", default=False,
                  help="just listen and display messages seen, do not contact a server or send announcements")
(options, args) = parser.parse_args()
LISTEN=options.listen
if len(args) == 0 and not LISTEN:
  parser.error("server must be specified (hostname or IP address)")
if len(args) > 2:
  parser.error("incorrect number of arguments")
if not LISTEN:
  SERVER=args[0]
INTERVAL=options.interval

try:
  # Roku device socket to query SSDP
  devicesock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  devicesock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
except OSError as e:
  print(f'Failed to create socket to device {SERVER}, detail: {e}')
  exit(1)

osock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
osock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
osock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
osock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
if options.localh:
  mreq = struct.pack("4sl", socket.inet_aton(MCAST_IF), socket.INADDR_ANY)
  osock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)

if options.sourceip:
  logging.info('Binding output sock to source IP: %s' % options.sourceip)
  # TODO: refactor to allow multiple soure ip bind, create a generic send function
  osock.bind((options.sourceip, 0))

imsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
imsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
imsock.bind(('', DLNA_PORT))
mreq = struct.pack("4sl", socket.inet_aton(DLNA_GRP), socket.INADDR_ANY)
imsock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


def sendudp(xsocket, ip, port, msg):
  print("Sending ("+ip+":"+str(port)+"): \n" + msg)
  xsocket.sendto(msg.encode(), (ip, port))


def notify(addr, port):
  if (URL != '' and UUID != '' and not LISTEN):
    # Note: responses should have ST:, notifies should have NT:
    # We include both

    msg = 'NOTIFY * HTTP/1.1' + CRLF \
	+ 'NT: urn:schemas-upnp-org:device:MediaServer:1' + CRLF \
	+ 'USN: uuid:' + UUID + '::urn:schemas-upnp-org:device:MediaServer:1' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'NOTIFY * HTTP/1.1' + CRLF \
	+ 'NT: upnp:rootdevice' + CRLF \
	+ 'USN: uuid:' + UUID + '::upnp:rootdevice' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'NOTIFY * HTTP/1.1' + CRLF \
	+ 'NT: uuid:' + UUID + CRLF \
	+ 'USN: uuid:' + UUID + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'NOTIFY * HTTP/1.1' + CRLF \
	+ 'NT: urn:schemas-upnp-org:service:ContentDirectory:1' + CRLF \
	+ 'USN: uuid:' + UUID + '::urn:schemas-upnp-org:service:ContentDirectory:1' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'NOTIFY * HTTP/1.1' + CRLF \
	+ 'NT: urn:schemas-upnp-org:service:ConnectionManager:1' + CRLF \
	+ 'USN: uuid:' + UUID + '::urn:schemas-upnp-org:service:ConnectionManager:1' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'NOTIFY * HTTP/1.1' + CRLF \
	+ 'NT: urn:schemas-upnp-org:service:X_MS_MediaReceiverRegistrar:1' + CRLF \
	+ 'USN: uuid:' + UUID + '::urn:schemas-upnp-org:service:X_MS_MediaReceiverRegistrar:1' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)
  else:
    print("Skipping notification")

def respond(addr, port):
  if (URL != '' and UUID != '' and not LISTEN):
    # Note: responses should have ST:, notifies should have NT:
    # We include both

    msg = 'HTTP/1.1 200 OK' + CRLF \
	+ 'ST: urn:schemas-upnp-org:device:MediaServer:1' + CRLF \
	+ 'USN: uuid:' + UUID + '::urn:schemas-upnp-org:device:MediaServer:1' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'HTTP/1.1 200 OK' + CRLF \
	+ 'ST: upnp:rootdevice' + CRLF \
	+ 'USN: uuid:' + UUID + '::upnp:rootdevice' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'HTTP/1.1 200 OK' + CRLF \
	+ 'ST: uuid:' + UUID + CRLF \
	+ 'USN: uuid:' + UUID + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'HTTP/1.1 200 OK' + CRLF \
	+ 'ST: urn:schemas-upnp-org:service:ContentDirectory:1' + CRLF \
	+ 'USN: uuid:' + UUID + '::urn:schemas-upnp-org:service:ContentDirectory:1' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'HTTP/1.1 200 OK' + CRLF \
	+ 'ST: urn:schemas-upnp-org:service:ConnectionManager:1' + CRLF \
	+ 'USN: uuid:' + UUID + '::urn:schemas-upnp-org:service:ConnectionManager:1' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)

    msg = 'HTTP/1.1 200 OK' + CRLF \
	+ 'ST: urn:schemas-upnp-org:service:X_MS_MediaReceiverRegistrar:1' + CRLF \
	+ 'USN: uuid:' + UUID + '::urn:schemas-upnp-org:service:X_MS_MediaReceiverRegistrar:1' + CRLF \
	+ 'NTS: ssdp:alive' + CRLF \
	+ 'LOCATION: ' + URL + CRLF \
	+ 'HOST: 239.255.255.250:1900' + CRLF \
	+ 'SERVER: ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ 'CACHE-CONTROL: max-age=' + str(INTERVAL * 10) + CRLF \
	+ CRLF
    sendudp(osock, addr, port, msg)
  else:
    print("Skipping response")

def server():
  if not LISTEN:
    msg = ('M-SEARCH * HTTP/1.1' + CRLF \
	+ 'Host: %s:%d' + CRLF \
	+ 'Man: "ssdp:discover"' + CRLF \
	+ 'ST: upnp:rootdevice' + CRLF \
	+ 'MX: 3' + CRLF \
	+ 'User-Agent:ssdp-fake/0 DLNADOC/1.50 UPnP/1.0 ssdp-fake/0' + CRLF \
	+ CRLF) % (SERVER, DLNA_PORT)
    logging.info("Sending SSDP search to upstream server")
    sendudp(devicesock, SERVER, DLNA_PORT, msg)

def parse_msg(msg_binary):
  global URL, UUID, last_update, next_notification
  msg = msg_binary.decode()
  if (re.match('^HTTP/1.1\s*200\s*OK', msg, re.IGNORECASE)):
    # Response to our M-SEARCH
    match = re.search(r'^LOCATION:\s*(.*)\r$', msg, re.IGNORECASE | re.MULTILINE)
    if match:
      URL = match.group(1)
    match = re.search(r'^USN:\s*uuid:([^:]+):', msg, re.IGNORECASE | re.MULTILINE)
    if match:
      UUID = match.group(1)
    print('URL=%s, UUID=%s.' % (URL, UUID))
    last_update = time.time()
    # Bring the notifcation forward
    next_notification = time.time() + 1
    
def is_search(msg):
  return re.match('^M-SEARCH', msg.decode(), re.IGNORECASE)

# Get info from server
last_update = 0
server()

next_notification = time.time() + INTERVAL

# Note: the port is not set up until at least one send has happened
#(notused, oport) = osock.getsockname()
(notused, oport) = devicesock.getsockname()

isock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
isock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
isock.bind(('', oport))

while True:
  logging.debug('Select timeout: %d' % max(next_notification - time.time(),0))
  (readyin, notused, notused) = select.select([isock, imsock], [], [], max(next_notification - time.time(),0))

  if (isock in readyin):
    (msg, (addr, port)) = isock.recvfrom(4096)
    print("Received unicast from %s:%d\n%s" % (addr, port, msg))
    if (is_search(msg)):
      respond(addr, port)
    else:
      parse_msg(msg)

  if (imsock in readyin):
    (msg, (addr, port)) = imsock.recvfrom(4096)
    if (port == oport):
      print("Ignored multicast from ourselves (%s:%d)" % (addr, port))
    else:
      print("Received multicast from %s:%d\n%s" % (addr, port, msg))
      if (is_search(msg)):
        respond(addr, port)

  logging.debug('Current time %s, next notif %s' % (time.time(), next_notification))
  if (time.time() >= next_notification):
    next_notification = time.time() + INTERVAL

    # Has the server info been updated recently?
    if (time.time() - last_update <= INTERVAL):
      # Yes, just do the notification
      logging.debug('Seding SSDP Notify')
      notify(DLNA_GRP, DLNA_PORT)
    else:
      # Get new info from the server
      server()


