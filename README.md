# arpitraryd

This program re-implements the functionality of [arpcatch](http://www.openbsd.org/4.3_packages/sh/arpcatch-19970824.tgz-long.html) daemon in OpenBSD.

The configuration file format is thus:

<pre>
[global]
iface=eth0 # the interface to listen on. will be put in to promiscuous 
       # mode by SCAPY

[mappings]
192.0.2.1=ab:ab:ab:ab:ab:ab # define your mappings here in the 
.....               # form IP=MAC 
</pre>

It ran for more than 5 years on a small LAN (~100 machines) which had 
previously been served by an OpenBSD box running arpcatch.  Nothing has exploded 
yet, but you run this code at your own risk. This package is released in to 
the public domain.

This package depends on [SCAPY](http://www.secdev.org/projects/scapy/) and doesn't actually work with the current SCAPY release :(
