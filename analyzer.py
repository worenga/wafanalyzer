#!/usr/bin/env python

import sys
import json
import requests
import argparse
import config

from waf import Waf

def getParser():
	parser = argparse.ArgumentParser(description = 'Process WAF events.')
	parser.add_argument('-u', '--user', metavar = 'user', dest = 'user',
						type = str, help = 'The user account')
	parser.add_argument('-k', '--key', metavar = 'key', dest = 'key',
						type = str, help = 'The API key')
	parser.add_argument('-z', '--zone', metavar = 'zone', dest = 'zone',
						type = str, help = 'The zone ID')
	parser.add_argument('-o', '--org', metavar = 'org', dest = 'org',
						type = str, help = 'The organization ID')
	parser.add_argument('-a', '--all', action = 'store_true', dest = 'all', 
						help = 'All zones (overwrites zone ID)', default = False)
	parser.add_argument('-s', '--separate', action = 'store_true',
						dest = 'separate', help = 'Separate reports', default = False),
	parser.add_argument('-r', '--ray', metavar = 'ray', dest = 'ray',
						type = str, help = 'The ray ID')
	return parser

def getZoneInteractive(waf):
	print "\nThe following zones are available:\n"
	for i, zone in enumerate(waf.zones):
		print "%s. ID: %s - %s" % (i + 1, zone[0], zone[1])
	while True:
		try:
			s = int(raw_input("\nPlease enter the list number:")) - 1
			zone = waf.zones[s][0]
			break
		except (ValueError, IndexError):
			print "Error: Invalid input. Try again."
	return zone

def printTopEvents(waf):
	print "Total events checked: " + str(len(waf.events)) + "\n"
	waf.printTopEvents("Top Country Threats:", 'country')
	waf.printTopEvents("Top IP Threats:", 'ip')
	waf.printTopEvents("Top URL Threats:", ('host', 'uri'))
	waf.printTopEvents("Top User Agent Threats:", 'user_agent')
	waf.printTopRules("Top Rule Hits:")

def printRayEvent(waf, ray):
	waf.printRay(ray)

def commandLineRunner():
	parser = getParser()
	args = parser.parse_args()

	# Favor command line over config
	USER  = args.user   if args.user   is not None else config.USER
	KEY   = args.key    if args.key    is not None else config.KEY
	ZONE  = args.zone   if args.zone   is not None else config.ZONE
	ORG   = args.org    if args.org    is not None else config.ORG
	PAGES = config.MAXP if config.MAXP is not None else 10
	ALL   = args.all
	SEP   = args.separate

	# If nothing specified default to interactive
	USER = USER if USER else raw_input("Enter your username:")
	KEY  = KEY  if KEY  else raw_input("Enter your API key:")

	# Create WAF object
	waf = Waf(USER, KEY, PAGES)

	if not ZONE and not ORG and not ALL:
		ZONE = [getZoneInteractive(waf)]
	elif ORG and not ALL:
		ZONE = [zone[0] for zone in waf.zones if zone[2] == ORG]
	elif ZONE:
		ZONE = [ZONE]
	else: 
		ZONE = [zone[0] for zone in waf.zones]

	# Perform relevant action and fetch data
	waf.zone = ZONE

	# Looking for specific ray
	if args.ray:
		printRayEvent(waf, args.ray)

	# We want individual reports per zone
	elif SEP and len(ZONE) > 1:
		for id in ZONE:
			for zone in waf.zones:
				if zone[0] == id:
					print "\nStarted grabbing WAF data for " + \
						zone[1] + " - ZoneID: " + id
			waf2 = Waf(USER, KEY, PAGES)
			waf2.zone = [id]
			if len(waf2.events) == 0: 
				print "No data for this zone.\n"
			printTopEvents(waf2)

	# Aggregate reports
	else:
		if len(waf.events) == 0: 
			print "No data for this zone.\n"
		printTopEvents(waf)


if __name__ == '__main__':
	commandLineRunner()