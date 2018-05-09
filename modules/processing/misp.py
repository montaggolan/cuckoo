# Copyright (C) 2010-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging
import os.path

import ipaddress
import json

try:
    import pymisp
    HAVE_MISP = True
except ImportError:
    HAVE_MISP = False

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger("myPyMISPloggerProcessing")

class MISP(Processing):
    """Enrich Cuckoo results with MISP data."""
    order = 3

    def search_ioc(self, ioc, check_flag=None):
        ioc_blacklist = json.load(open(self.options.get("ioc_blacklist")))

        if check_flag == 'hash':
            # not implemented yet
            pass
        elif check_flag == 'network':
            try:
                ipaddr = ipaddress.ip_address(unicode(ioc, "utf-8"))
                for i in ioc_blacklist["CIDR"]:
                    if ipaddr in ipaddress.ip_network(ipaddress.ip_network(i.split(';')[0])):
                        log.info("CIDR Blacklist %s" % str(ioc))
                        return
                for i in ioc_blacklist["Range"]:
                    [ipa for ipa in ipaddress.summarize_address_range(ipaddress.IPv4Address(i.split(';')[0]), ipaddress.IPv4Address(i.split(';')[1]))]
                    if ipaddr in ipaddress.ip_network(ipa):
                        log.info("Network range Blacklist %s" % str(ioc))
                        return
                for i in ioc_blacklist["IP"]:
                    if i in ioc:
                        log.info("IP Blacklist %s" % str(ioc))
                        return
            except:
                for i in ioc_blacklist["Domain"]:
                    if i in ioc:
                        log.info("Domain Blacklist %s" % str(ioc))
                        return
                for i in ioc_blacklist["IP"]:
                    if i in ioc:
                        log.info("IP Blacklist %s" % str(ioc))
                        return

        try:
            r = self.misp.search_all(ioc)
        except Exception as e:
            log.debug("Error searching for IOC (%r) on MISP: %s", ioc, e)
            return

        if not r:
            return

        for row in r.get("response", []):
            event = row.get("Event", {})
            event_id = event.get("id")

	    only_ids = True
            if self.options.get("only_ids", 'yes') == 'no':
                only_ids = False

            #log.warning("MISP Debug: only_ids = %s" % only_ids)

            for attribute in event.get("Attribute"):
		        if attribute['value'] == ioc:
                    if not(only_ids and not attribute['to_ids']):
                        if event_id not in self.iocs:
                            url = os.path.join(self.url, "events/view", "%s" % event_id)
                            self.iocs[event_id] = {
                                "event_id": event_id,
                                "date": event.get("date"),
                                "url": url,
                                "level": event.get("threat_level_id"),
                                "info": event.get("info", "").strip(),
                                "iocs": [],
                            }

                        if ioc not in self.iocs[event_id]["iocs"]:
                            log.warning("MISP Debug: Added IOC %s" % ioc)
                            # EOP
                            self.iocs[event_id]["iocs"].append(ioc)

    def _parse_date(self, row):
        if not row.get("date"):
            return datetime.datetime.now()

        return datetime.datetime.strptime(row["date"], "%Y-%m-%d")

    def run(self):
        """Run analysis.
        @return: MISP results dict.
        """

        if not HAVE_MISP:
            raise CuckooDependencyError(
                "Unable to import PyMISP (install with `pip install pymisp`)"
            )

        self.url = self.options.get("url", "")
        self.apikey = self.options.get("apikey", "")
        maxioc = int(self.options.get("maxioc", 100))

        if not self.url or not self.apikey:
            raise CuckooProcessingError(
                "Please configure the URL and API key for your MISP instance."
            )

        self.key = "misp"
        self.iocs = {}
        self.iocs_network = {}
        self.iocs_hashes = {}

        self.misp = PyMISP(self.url, self.apikey, False, "json")
        iocs = set()
        iocs_network = set()
        iocs_hashes = set()

        iocs.add(self.results.get("target", {}).get("file", {}).get("md5"))
        iocs_hashes.add(self.results.get("target", {}).get("file", {}).get("md5"))

        for dropped in self.results.get("dropped", []):
            iocs.add(dropped.get("md5"))
            iocs_hashes.add(dropped.get("md5"))

        iocs.update(self.results.get("network", {}).get("hosts", []))
        iocs_network.update(self.results.get("network", {}).get("hosts", []))

        for block in self.results.get("network", {}).get("domains", []):
            iocs.add(block.get("ip"))
            iocs_network.add(block.get("ip"))
            iocs.add(block.get("domain"))
            iocs_network.add(block.get("domain"))


        # Remove empty entries and turn the collection into a list.
        iocs = list(iocs.difference((None, "")))
        iocs_hashes = list(iocs_hashes.difference((None, "")))
        iocs_network = list(iocs_network.difference((None, "")))

        # Acquire all information related to IOCs.
        # hash blacklist not used atm
        #for ioc in iocs_hashes[:maxioc]:
            #self.search_ioc(ioc, "hash")

        for ioc in iocs_network[:maxioc]:
            print ioc
            self.search_ioc(ioc, "network")

        # Sort IOC information by date and return all information.
        return sorted(
            self.iocs.values(), key=self._parse_date, reverse=True
        )
