""""
Performs whois-lookup and generates a report out of it.
"""

__author__ = "Jayakumar M"

__email__ = "jai6684@yahoo.com"

__version__ = "1.0"


import re
import csv
import argparse
import logging

from ipwhois import IPWhois
from ipwhois.exceptions import BaseIpwhoisException as IpwhoisException


logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)


def main():
    """
    Entry point for script.
    :return: None
    """

    parser = argparse.ArgumentParser(description="Run whois check for IP addresses",
                                     usage="python whoislookup.py -r SSH_successful_Logon_attempts.txt "
                                           "[or] python whoislookup.py -f ip_addresses.txt")

    parser.add_argument("-o",
                        "--report-name",
                        action="store",
                        required=True,
                        dest="report_name",
                        help="")

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-f",
                       "--filename",
                       action="store",
                       dest="filename",
                       help="File to be checked with one IP per line")

    group.add_argument("-r",
                       "--grep",
                       action="store",
                       dest="grep",
                       help="")

    args = parser.parse_args()

    if args.filename:
        logging.info("performing whois lookup for IP addresses in %s", args.filenme)

        with open(args.filename) as f:
            ip_addresses = f.read().replace(" ", "").split("\n")
            write_report(args.report_name, get_records(ip_addresses))

    if args.grep:
        logging.info("performing whois lookup for IP addresses in %s", args.grep)

        with open(args.grep) as f:
            pattern = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
            matches = map(lambda line: re.search(pattern, line), f)
            matches = filter(lambda match: match, matches)
            ip_addresses = set(map(lambda match: match.group(), matches))
            write_report(args.report_name, get_records(ip_addresses))


def do_whois_lookup(ip_address):
    """
    Do the whois lookup for given IP address.
    :param ip_address: IP address to be whois-looked up.
    :return: Response object for the lookup.
    """
    logging.info("performing whois lookup for %s", ip_address)

    try:
        return IPWhois(ip_address).lookup_whois()
    except IpwhoisException:
        logging.exception("IP whois lookup failed for %s", ip_address)


def do_whois_bulk_lookup(ip_addresses):
    """
    Do the bulk whois lookup for list of IP addresses.
    :param ip_addresses: list of IP addresses to be whois-looked up.
    :return: Sequence of response objects for the lookups.
    """
    return map(do_whois_lookup, ip_addresses)


def get_records(ip_addresses):
    """
    Extract only necessary fields from the whois-lookup response.
    :param ip_addresses: list of IP addresses to be whois-looked up.
    :return: generator for sequence of tuples containing necessary fields from the whois-lookup response.
    """
    for record in do_whois_bulk_lookup(ip_addresses):
        if record:
            ip_address = record.get("query", "")
            asn = record.get("asn", "")

            for net in record.get("nets", []):
                cidr = net.get("cidr", "") or ""
                org_name = net.get("name", "") or ""
                network_ange = net.get("range", "") or ""
                address = net.get("address", "") or ""
                city = net.get("city", "") or ""
                state = net.get("state", "") or ""
                country = net.get("country", "") or ""

                address = address.replace("\n", " ")

                yield ip_address, asn, cidr, org_name, network_ange, address, city, state, country


def write_report(filename, records):
    """
    Write the whois-lookup response as table into a csv file.
    :param filename: output file name.
    :param records: sequence of data (as tuple) from whois-lookup responses.
    :return: None
    """

    headers = ("IP ADDRESS", "ASN", "CIDR", "ORG NAME", "NETWORK RANGE", "ADDRESS", "CITY", "STATE", "COUNTRY")

    with open(filename, "w") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(headers)

        for record in records:
            writer.writerow(record)

    logging.info("report is writen to %s", filename)


if __name__ == '__main__':

    try:
        main()
    except Exception:
        logging.exception("something went wrong..")

