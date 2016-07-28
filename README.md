# rwhois
Reverse whois query tool

$ ./rwhois.py -h
usage: rwhois.py [-h] -term [TERMS [TERMS ...]] [-nmap] [-remove]

Queries reverse whois for term(s) specified and returns a dictionary of
domains for that term. Also an optional flag to run an nmap scan results of
each domain

optional arguments:
  -h, --help            show this help message and exit
  -term [TERMS [TERMS ...]], -terms [TERMS [TERMS ...]], --t [TERMS [TERMS ...]]
                        single term or space separated terms
  -nmap, --n            Flag to specify whether you want nmap results on the
                        domains returned
  -remove, --r          Removes results that returned no open ports
