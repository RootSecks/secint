#!/usr/bin/python


import imp
import _mysql
import sys
import argparse
import subprocess
import os
import secintdata
import secintdisplay
import secintscans

APP_PATH = os.path.abspath(os.path.dirname(__file__))


def main():
    parser = argparse.ArgumentParser(
        description="Security Intellegence Framework")

    mutgroup = parser.add_mutually_exclusive_group(required=True)

    mutgroup.add_argument(
        '-lH', '--listhosts', help="List host", action='store_true')  # LIST HOSTS
    mutgroup.add_argument(
        '-lN', '--listnetworks', help="List Networks", action='store_true')  # LIST NETWORKS
    mutgroup.add_argument(
        '-lS', '--listservices', help="List Services", action='store_true')  # LIST SERVICES

    mutgroup.add_argument(
        '-pH', '--promotehost', help="Promote host from a scan to a secint host")  # PRMOTE SECINT HOST
    mutgroup.add_argument(
        '-uH', '--updatehost', help="Update the status effects of a host", action='store_true')  # UPDATE SECINT HOST

    mutgroup.add_argument(
        '-sN', '--scannmap', help="Perform nmap scan")  # NMAP SCAN

    parser.add_argument(
        '-nt', '--notitle',
        help='Surpresses column titles to make output suitable for scripts',
        action='store_true')
    parser.add_argument(
        '-nT', '--notable', help='Output as pretty table', action='store_true')

    parser.add_argument(
        'filter', type=str, nargs='?', help='Filters output lists')
    args = parser.parse_args()

    if (args.listhosts):
        data_handler = secintdata.DataHandler()
        host_list = data_handler.get_hosts()
        secintdisplay.ListHosts(
            host_list, args.notable, args.notitle, args.filter)
    elif (args.scannmap is not None):
        scan_result = secintscans.NmapScan(args.scannmap)
        print scan_result
    elif (args.listnetworks):
        data_handler = secintdata.DataHandler()
        network_list = data_handler.get_networks()
        secintdisplay.ListNetworks(
            network_list, args.notable, args.notitle, args.filter)
    elif (args.listservices):
        data_handler = secintdata.DataHandler()
        host_list = data_handler.get_hosts()
        secintdisplay.ListServices(
            host_list, args.notable, args.notitle, args.filter)

if __name__ == "__main__":
    main()
