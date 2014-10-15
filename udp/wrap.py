#!/usr/bin/env python
#
# Proof of Concept: UDP Hole Punching
# Two client connect to a server and get redirected to each other.
#
# This is the client.
#
# Koen Bollen <meneer koenbollen nl>
# 2010 GPL
#
# modified to wrap GGPOFBA without portforwarding by Pau Oliva (@pof)
# 2014 GPL
#

import sys
import socket
import struct

def bytes2addr( bytes ):
    """Convert a hash to an address pair."""
    if len(bytes) != 6:
        raise ValueError, "invalid bytes"
    host = socket.inet_ntoa( bytes[:4] )
    port, = struct.unpack( "H", bytes[-2:] )
    return host, port

def main():

    port = 7001
    l_sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    l_sockfd.bind( ("", port) )
    print "listening on *:%d (udp)" % port

    emudata, emuaddr = l_sockfd.recvfrom(0)
    print "connection from %s:%d" % emuaddr

    try:
        master = (sys.argv[1], int(sys.argv[2]))
        quark = sys.argv[3].strip()
    except (IndexError, ValueError):
        print >>sys.stderr, "usage: %s <host> <port> <quark>" % sys.argv[0]
        sys.exit(65)

    sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    sockfd.sendto( quark, master )
    data, addr = sockfd.recvfrom( len(quark)+3 )
    if data != "ok "+quark:
        print >>sys.stderr, "unable to request!"
        sys.exit(1)
    sockfd.sendto( "ok", master )
    print >>sys.stderr, "request sent, waiting for partner in quark '%s'..." % quark
    data, addr = sockfd.recvfrom( 6 )

    target = bytes2addr(data)
    print >>sys.stderr, "connected to %s:%d" % target

    while True:

        emudata, emuaddr = l_sockfd.recvfrom(1024)
        if data:
            #print "* received [ %r ] from %s" % (emudata, emuaddr)
            sockfd.sendto( emudata, target )
            #print "* sent [ %r ] to %s" % (emudata, target)

        peerdata, peeraddr = sockfd.recvfrom( 1024 )
        if peerdata:
            #print "* received [ %r ] from %s" % (peerdata, peeraddr)
            l_sockfd.sendto( peerdata, emuaddr )
            #print "* sent [ %r ] to %s" % (peerdata, emuaddr)

    sockfd.close()
    l_sockfd.close()

if __name__ == "__main__":
    main()

# vim: expandtab shiftwidth=4 softtabstop=4 textwidth=79:
