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

import sys
import socket
from select import select
import struct

def bytes2addr( bytes ):
    """Convert a hash to an address pair."""
    if len(bytes) != 6:
        raise ValueError, "invalid bytes"
    host = socket.inet_ntoa( bytes[:4] )
    port, = struct.unpack( "H", bytes[-2:] )
    return host, port

def main():
    try:
        master = (sys.argv[1], int(sys.argv[2]))
        pool = sys.argv[3].strip()
    except (IndexError, ValueError):
        print >>sys.stderr, "usage: %s <host> <port> <pool>" % sys.argv[0]
        sys.exit(65)

    sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    sockfd.sendto( pool, master )
    data, addr = sockfd.recvfrom( len(pool)+3 )
    if data != "ok "+pool:
        print >>sys.stderr, "unable to request!"
        sys.exit(1)
    sockfd.sendto( "ok", master )
    print >>sys.stderr, "request sent, waiting for parkner in pool '%s'..." % pool
    data, addr = sockfd.recvfrom( 6 )

    target = bytes2addr(data)
    print >>sys.stderr, "connected to %s:%d" % target

    while True:
        rfds,_,_ = select( [0, sockfd], [], [] )
        if 0 in rfds:
            data = sys.stdin.readline()
            if not data:
                break
            sockfd.sendto( data, target )
        elif sockfd in rfds:
            data, addr = sockfd.recvfrom( 1024 )
            sys.stdout.write( data )

    sockfd.close()

if __name__ == "__main__":
    main()

# vim: expandtab shiftwidth=4 softtabstop=4 textwidth=79:
