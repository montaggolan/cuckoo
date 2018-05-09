# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import logging
import shlex
import warnings
import ntpath
import ipaddress
import json

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import pymisp
    HAVE_MISP = True
except ImportError:
    HAVE_MISP = False

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger("PyMISPLoggerReporting")
ioc_blacklist = None

class MISP(Report):
    """Enrich MISP with Cuckoo results."""

    def sample_hashes(self, results, event):
        """For now only reports hash of the analyzed file, not of the dropped
        files, as we may have hundreds or even thousands of dropped files, and
        the misp.add_hashes() method doesn't accept multiple arguments yet."""

        if results.get("target", {}).get("file", {}):
            f = results["target"]["file"]
            self.misp.add_hashes(
                event,
                category="Payload delivery",
                filename=f["name"],
                md5=f["md5"],
                sha1=f["sha1"],
                sha256=f["sha256"],
                comment="File submitted to Cuckoo",
                to_ids=False,
            )

    def dropped_hashes(self, results, event):
        """Add functionality that sample_hashes lacks like the comment points out.
        A simple whitelist exclusion list is used to include interesting files only
        to limit amount of data sent to MISP. Might get very noisy.
        """
        ewf = self.options.get("extensions_whitelist")
        with open(ewf, 'r') as f:
            extensions_whitelist = f.read().splitlines()

        for i in results.get("dropped", {}):
            try:
                fp = str(i["filepath"])
                if str(os.path.splitext(fp)[1]).lower() in extensions_whitelist:
                    self.misp.add_hashes(
                        event,
                        category="Artifacts dropped",
                        filename=ntpath.basename(fp),
                        md5=i["md5"],
                        sha1=i["sha1"],
                        sha256=i["sha256"],
                        comment="Dropped file.",
                        to_ids=False,
                    )

                    self.misp.add_filename(
                        event,
                        category="Artifacts dropped",
                        filename=i["filepath"],
                    )
            except:
                continue

    def maldoc_network(self, results, event):
        """Specific reporting functionality for malicious documents. Most of
        this functionality should be integrated more properly in the Cuckoo
        Core rather than being abused at this point."""
        urls = set()
        for signature in results.get("signatures", []):
            if signature["name"] != "malicious_document_urls":
                continue

            for mark in signature["marks"]:
                if mark["category"] == "url":
                    urls.add(mark["ioc"])

        self.misp.add_url(event, sorted(list(urls)))

    def all_urls(self, results, event):
        """All of the accessed URLS as per the PCAP. *Might* have duplicates
        when compared to the 'maldoc' mode, but e.g., in offline mode, when no
        outgoing traffic is allowed, 'maldoc' reports URLs that are not present
        in the PCAP (as the PCAP is basically empty)."""
        urls = set()
        ioc_blacklist_file = self.options.get("ioc_blacklist")
        blacklisted = False

        global ioc_blacklist
        if not ioc_blacklist:
            ioc_blacklist=json.load(open(ioc_blacklist_file))


        for protocol in ("http_ex", "https_ex"):
            for entry in results.get("network", {}).get(protocol, []):
                if self._blacklist_check(entry["host"], "host"):
                    log.info("Found blacklisted host: %s" % entry["host"])
                    blacklisted = True
                    break

                if blacklisted:
                    blacklisted = False
                    continue

                urls.add("%s://%s%s" % (
                    entry["protocol"], entry["host"], entry["uri"]
                ))

        self.misp.add_url(event, sorted(list(urls)), category='Network activity', to_ids=False)

    def domain_ipaddr(self, results, event):
        global ioc_blacklist
        if not ioc_blacklist:
            ioc_blacklist=json.load(open(self.options.get("ioc_blacklist")))

        domains_and_ips, domains_only, ips = {}, set(), set()
        blacklisted = False

        for domain in results.get("network", {}).get("domains", []):
            if self._blacklist_check(domain["domain"], "host"):
                blacklisted = True
                break

            if blacklisted:
                blacklisted = False
                continue

            if not domain["ip"]:
                domains_only.add(domain["domain"])
                continue
            domains_and_ips[domain["domain"]] = domain["ip"]
            ips.add(domain["ip"])

        ipaddrs = set()
        for ipaddr in results.get("network", {}).get("hosts", []):
            if ipaddr not in ips:
                if not self._blacklist_check(ipaddr, "IP"):
                    ipaddrs.add(ipaddr)

        self.misp.add_domains_ips(event, domains_and_ips, category='Network activity', to_ids=False)
        self.misp.add_ipdst(event, sorted(list(ipaddrs)), category='Network activity', to_ids=False)
        self.misp.add_domain(event, sorted(list(domains_only)), category='Network activity', to_ids=False)

    def run(self, results):
        """Submits results to MISP.
        @param results: Cuckoo results dict.
        """
        url = self.options.get("url")
        apikey = self.options.get("apikey")
        mode = shlex.split(self.options.get("mode") or "")

        if not url or not apikey:
            raise CuckooProcessingError(
                "Please configure the URL and API key for your MISP instance."
            )

        self.misp = pymisp.PyMISP(url, apikey, False, "json")

        sample_filename=os.path.basename(self.task["target"])

        distribution = self.options.get("distribution") or 0
        threat_level = self.options.get("threat_level") or 4
        analysis = self.options.get("analysis") or 0

        event = self.misp.new_event(
            distribution = distribution,
            threat_level_id = threat_level,
            analysis = analysis,
            info="Cuckoo Sandbox analysis for %s (#%d)" % (sample_filename, self.task["id"]),
        )

        if results.get("target", {}).get("category") == "file":
            self.misp.upload_sample(
                filename=sample_filename,
                filepath_or_bytes=self.task["target"],
                event_id=event["Event"]["id"],
                distribution=distribution,
                to_ids=False,
                category="External analysis",
            )

        if "hashes" in mode:
            self.sample_hashes(results, event)

        if "maldoc" in mode:
            self.maldoc_network(results, event)

        if "url" in mode:
            self.all_urls(results, event)

        if "ipaddr" in mode:
            self.domain_ipaddr(results, event)

        if "dropped" in mode:
            self.dropped_hashes(results, event)

        tag = self.options.get("tag")
	    if tag:
	        results = self.misp.add_tag(event, tag)
	        if results.has_key('message'):
	            log.warning("Cannot tag event: %s" % results['message'])


    def _blacklist_check(self, ioc, cat):
        global ioc_blacklist
        if cat == "IP":
            for i in ioc_blacklist["CIDR"]:
                if ipaddress.ip_address(unicode(ioc, "utf-8")) in ipaddress.ip_network(ipaddress.ip_network(i.split(';')[0])):
                    log.info("CIDR Blacklist %s" % str(ioc))
                    return True
            for i in ioc_blacklist["Range"]:
                [ipaddr for ipaddr in ipaddress.summarize_address_range(ipaddress.IPv4Address(i.split(';')[0]), ipaddress.IPv4Address(i.split(';')[1]))]
                if ipaddress.ip_address(unicode(ioc, "utf-8")) in ipaddress.ip_network(ipaddr):
                    log.info("Network range Blacklist %s" % str(ioc))
                    return True
            for i in ioc_blacklist["IP"]:
                if i in ioc:
                    log.info("IP Blacklist %s" % str(ioc))
                    return True
            return False
        elif cat == 'host':
            for i in ioc_blacklist["Domain"]:
                if i in ioc:
                    log.info("Domain Blacklist %s" % str(ioc))
                    return True
            for i in ioc_blacklist["IP"]:
                if i in ioc:
                    log.info("IP Blacklist %s" % str(ioc))
                    return True
            return False
        else:
            return False
