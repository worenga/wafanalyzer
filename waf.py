__version__ = '2018.6.1'

import sys
import json
import requests
import codecs
from collections import defaultdict

sys.stdout = codecs.getwriter('utf8')(sys.stdout)

class Waf(object):
    """Waf class.

    Provides an interface to the CloudFlare API only for WAF related 
    functions. Interal properties usually perform an API call and are
    cached internally.

    """

    # Internal flags
    ALL = "ALL"

    # API settings
    API     = "https://api.cloudflare.com/v4/"
    TIMEOUT = 30
    ROWS    = 15

    # WAF event fields
    FIELDS = {
        'Message'   : 'rule_message',
        'Country'   : 'country',
        'Location'  : 'cloudflare_location',
        'Duration'  : 'request_duration',
        'Protocol'  : 'protocol',
        'Time'      : 'occurred_at',
        'URI'       : 'uri',
        'Host'      : 'host',
        'User Agent': 'user_agent',
        'Client IP' : 'ip',
        'Action'    : 'action',
        'Method'    : 'method'
    }

    # WAF strings
    OWASP = 981176
    IPWAF = "IP Firewall"

    # Cached objects
    _events = None
    _zones  = None
    _oDesc  = {}

    def __init__(self, user, key, pages):
        self.user  = user
        self.key   = key
        self.pages = pages
        self.headers  = {
            'User-Agent'  : 'wafanalyzer-'+__version__, 
            'X-Auth-Key'  : self.key,
            'X-Auth-Email': self.user,
            'Content-Type': 'application/json'
        }

    @property
    def events(self):
        events = []

        if self._events is not None: return self._events

        for zone in self.zone:
            page   = 0
            pageId = ""
            url    = self.API + "zones/" + zone + "/firewall/events/"

            print >> sys.stderr, "Zone: " + zone
            while True:
                print >> sys.stderr, "Fetching page " + str(page + 1)

                response = self.api(url, {
                    "page"    : page,
                    "per_page": 50,
                    "page_id" : pageId
                })

                # Some book keeping
                new = []
                for event in response['result']:

                    # Clean IP Firewall descriptions
                    if event['rule_id'] is None:
                        event['rule_id']      = ""
                        event['rule_message'] = self.IPWAF

                    # Get OWASP descriptions (ugly)
                    for rId in event['triggered_rule_ids']:
                        if not rId in self._oDesc and rId not in new:
                            new.append(rId)
                if new:
                    self.getRuleDescription(zone, new)

                page    += 1
                events  += response['result']
                pageId   = response['result_info']['next_page_id']

                if len(response['result']) == 0 or page is None or \
                        pageId is None or page + 1 > self.pages:
                    break

        print
        self._events = events
        return events

    @property
    def zones(self):
        zones = []
        url   = self.API + "zones/?per_page=900"

        if self._zones is not None: return self._zones

        response = self.api(url)
        count    = response["result_info"]["total_count"]
        zoneDict = response["result"]

        for zone in zoneDict:
            zones.append([zone["id"], zone["name"], zone['owner']['id']])

        return zones

    def api(self, url, params = {}):
        try:
            response = requests.get(url,
                headers = self.headers,
                params  = params,
                timeout = self.TIMEOUT
            )
        except requests.exceptions.RequestException:
            sys.exit('Error: ...')

        # TODO: Deal with error codes
        code = response.status_code
        if code != 200 and code != 400: sys.exit('Error: ...')

        return json.loads(response.text)

    def sortData(self, data, crop):
        return sorted(data.items(), key = lambda x:x[1], reverse = True)[:crop]

    def topEvents(self, keys):
        data = defaultdict(int)
        for event in self.events:
            tKey = ""

            # Combine keys if multiple given
            if type(keys) is tuple:
                for key in keys:
                    tKey += event[key]
            else:
                tKey = event[keys]
            data[tKey] += 1

        return self.sortData(data, self.ROWS)

    def printTopEvents(self, title, keys):
        print title + "\n"
        for j, k in self.topEvents(keys):
            if j is None:
                j = ""
            print "- " + str(k) + " Hits: " + j
        print

    def topRules(self):
        rData = defaultdict(int)
        oData = defaultdict(int)
        rDesc = []
        for event in self.events:

            rData[event['rule_id'] + " " + event['rule_message']] += 1

            for owasp in event["triggered_rule_ids"]:
                oData[owasp] += 1

        return (self.sortData(rData, self.ROWS), self.sortData(oData, self.ROWS))

    def getRuleDescription(self, zone, rule):
        desc = {}

        # Accept more than one rule
        if type(rule) is list:
            rule = ",".join(rule)

        # TODO: will break with more than 25 IDs
        url  = self.API + "zones/" + zone + "/firewall/ruleinfo?ids=" + rule

        for r in self.api(url)['result']:
            self._oDesc[r['id']] = r['description']

    def printTopRules(self, title):
        print title + "\n"
        data  = self.topRules()
        oDone = False

        for rule in data[0]:
            print "- " + str(rule[1]) + " Hits: " + rule[0]

            # Print OWASP information
            if rule[0].startswith(str(self.OWASP)) and not oDone:
                oDone = True
                print "  OWASP Rule Details:"
                for oRule in data[1]:
                    print "\t- " + str(oRule[1]) + " Hits: " + \
                        oRule[0] + " " + self._oDesc[oRule[0]]

    def printRay(self, id):
        for zone in self.zone:
            url      = self.API + "zones/" + zone + "/firewall/events/" + id
            response = self.api(url)
            if response['success']:
                print "WAF details for ray " + id + ":\n"
                event = response['result']
                for field in self.FIELDS:
                    print '{0:12} {1:10}'.format(field + ":",
                        str(event[self.FIELDS[field]]))
                return
        print "WAF event not found.\n"
