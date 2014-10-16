ggposrv.py
==========

Unofficial ggpo server (re)implementation

&copy; 2014 Pau Oliva Fora ([@pof](https://twitter.com/pof))

# Usage
<pre>
$ ./ggposrv.py -h
-!- ggpo-ng server version 0.4
-!- (c) 2014 Pau Oliva Fora (@pof) 
Usage: ./ggposrv.py [option]

Options:
  -h, --help            show this help message and exit
  --start               Start ggposrv (default)
  --stop                Stop ggposrv
  --restart             Restart ggposrv
  -a LISTEN_ADDRESS, --address=LISTEN_ADDRESS
                        IP to listen on
  -p LISTEN_PORT, --port=LISTEN_PORT
                        Port to listen on
  -V, --verbose         Be verbose (show lots of output)
  -l, --log-stdout      Also log to stdout
  -f, --foreground      Do not go into daemon mode.
  -u, --udpholepunch    Use UDP hole punching.
</pre>

# Compatibility
This server is fully compatible with existing GGPO clients and the official GGPOFBA emulator, however if [UDP hole punching](http://www.brynosaurus.com/pub/net/p2pnat/) is enabled the GGPOFBA emulator needs to be proxyied through a [wrapper](https://github.com/poliva/ggposrv/tree/master/udp). The wrapper is available in the udp folder. UDP hole punching is a popular NAT traversal technique that allows to connect two players without having to forward ports on the router, making the setup easier.
