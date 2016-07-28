#!/usr/bin/env python

import argparse
import pprint

import netutils

tool_desc = "Queries reverse whois for term(s) specified and returns a dictionary of domains for that term. " \
            "Also an optional flag to run an nmap scan results of each domain"
parser = argparse.ArgumentParser(description=tool_desc)

parser.add_argument('-term', '-terms', '--t', dest='terms', nargs='*',
                    help="single term or space separated terms", required=True)

parser.add_argument('-nmap', '--n', dest='nmap', action="store_true", required=False, default=False,
                    help='Flag to specify whether you want nmap results on the domains returned')

parser.add_argument('-remove', '--r', dest='remove', action="store_true", required=False, default=True,
                    help='Removes results that returned no open ports')

args = parser.parse_args()

pp = pprint.PrettyPrinter(indent=4)
pp.pprint(netutils.query_rwhois(args.terms, args.nmap, args.remove))
