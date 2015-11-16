#!/usr/bin/python

# Michael Fincham <michael@unleash.co.nz> 2010-11-04

import ConfigParser, syslog, signal, sys
from scapy.all import *

mappings = {}
pcap_iface = ''

def signal_handler(signal, frame):
	syslog.syslog("Caught signal %i, shutting down" % signal)
	sys.exit(0)
	
def callback(packet):
	arp = packet[ARP]
	if arp.op == 1 and arp.pdst in mappings: # 1 is "who-has"
		reply_mac = mappings[arp.pdst]
	 	reply_arp = ARP(hwsrc=reply_mac, pdst = arp.psrc, psrc = arp.pdst, op=2)
	 	frame = Ether(dst=arp.hwsrc)
	 	sendp(frame / reply_arp, verbose = False, iface=pcap_iface)
	 	syslog.syslog("Poisoned %s with an entry for %s (%s)" % (arp.psrc,arp.pdst,reply_mac))
	 	print "Poisoned %s with an entry for %s (%s)" % (arp.psrc,arp.pdst,reply_mac)

if __name__ == "__main__":
	syslog.openlog('arpitraryd')
	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)
	syslog.syslog('Reading config file...');
	try:
		config = ConfigParser.RawConfigParser()
		config.read('arpitraryd.conf')
		for ip, mac in config.items('mappings'):
			mappings[ip] = mac
		pcap_iface = config.get('global','iface')
	except:
		syslog.syslog('An error reading the config file.')
		sys.exit(2)
	syslog.syslog("Starting pcap on %s" % pcap_iface)
	sniff(prn=callback, iface=pcap_iface, filter="arp", store=0)
