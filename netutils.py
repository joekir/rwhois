import socket

import requests
from bs4 import BeautifulSoup


def query_rwhois(search_terms, nmap=False, remove_entries=True):
    """
    Scrapes a reverse whois page for search_terms provided

    :return: dictionary of organisations and their live domains
    :rtype: dict
    """
    # Its one of the few free options for reverse whois
    base_url = "http://viewdns.info/reversewhois/?q="
    org_dict = dict()

    """
        Scrape the domains from the reverse whois lookup html table
    """
    for org in search_terms:
        r = requests.get(url=base_url + org)
        if r.ok:
            soup = BeautifulSoup(r.content, 'html.parser')
            domain_table = soup('table')[3]
            domain_list = [row('td')[0].string for row in domain_table.findAll('tr')]
            if domain_list and domain_list[0] is not None:
                domain_list.remove("Domain Name")  # filter the header
                org_dict[org] = domain_list

    """
        Next get rid of domains that are no longer dns resolvable.
        Using items() so we can delete while iterating
    """
    for org in org_dict.items():
        for domain in org[1]:
            try:
                socket.gethostbyname_ex(domain)[2]
            except:
                # case where there is no dns record
                org_dict[org[0]].remove(domain)

    if nmap:
        for org in org_dict.keys():
            for hostname in org_dict[org]:
                result = port_scan(hostname)
                assert isinstance(result, list)
                if result:
                    org_dict[org][org_dict[org].index(hostname)] = {hostname: result}
                else:
                    if remove_entries:
                        org_dict[org].remove(hostname)

    return org_dict


def port_scan(hostname, ports=[20, 21, 22, 23, 25, 53, 69, 80, 115, 443]):
    """
        Using the socket class to do our own lightweight port discovery.

        :param ports: defaults to list of common ports for speed on the TCP/IP scan
        :type ports: list
        :return: open_ports
        :rtype: list
    """
    open_ports = []
    socket.setdefaulttimeout(0.2)  # this may need to be tweaked if you have high latency

    #TODO - do a SYS scan instead, or something much faster than this!

    for port in ports:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((hostname, port))
            if result == 0:
                open_ports.append(port)
        except:
            pass

        if s:
            s.close()

    return open_ports
