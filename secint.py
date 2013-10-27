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
        '-lH', '--listhosts', help="List host",
        action='store_true')  # LIST HOSTS
    mutgroup.add_argument(
        '-lN', '--listnetworks', help="List Networks",
        action='store_true')  # LIST NETWORKS
    mutgroup.add_argument(
        '-lS', '--listservices', help="List Services",
        action='store_true')  # LIST SERVICES
    
    mutgroup.add_argument(
        '-hD', '--hostdetails', help="Show detailed "
        "host info", type=int) #SHOW DETAILED HOST INFORMATION

    mutgroup.add_argument(
        '-lSc', '--listscans', help="List scans",
        action='store_true')  # LIST SCANS
    mutgroup.add_argument(
        '-lSh', '--listscannedhosts', help="List scanned hosts",
        metavar="SCANID", type=int)  # LIST HOSTS FROM A SCAN
    mutgroup.add_argument(
        '-lSs', '--listscannedservices', help="List scanned services",
        metavar="SCANID", type=int)  # LIST SERVICES FROM A SCAN

    mutgroup.add_argument(
        '-lC', '--listcreds', help="List creds", action='store_true')

    mutgroup.add_argument(
        '-pH', '--promotehost', help="Promote host from"
        "a scan to a secint host", metavar="HOSTID", type=int)  # PRMOTE SECINT HOST
    mutgroup.add_argument(
        '-uH', '--updatehost', help="Update",
        metavar="HOSTID", type=int)  # UPDATE SECINT HOST
    mutgroup.add_argument(
        '-pN', '--promotenic', help="Promote a nic to "
        "an existing host from a scanned host", metavar="HOSTID", type=int)  # PROMOTE A HOST TO A NIC ON AN EXISTING HOST

    mutgroup.add_argument(
        '-cH', '--createhost', help="Create a host",
        action='store_true')
    mutgroup.add_argument(
        '-cNi', '--createnic', help="Create a nic", 
        metavar="HOSTID", type=int)
    mutgroup.add_argument(
        '-cS', '--createservice', help="Create a service",
        metavar="NICID", type=int)

    mutgroup.add_argument(
        '-aC', '--addcredential', help="Add credentials",
        action='store_true')

    mutgroup.add_argument(
        '-lHt', '--listhashetypes', help="List hash types",
        action='store_true')

    mutgroup.add_argument(
        '-cN', '--createnetwork', help="Create network", action='store_true')

    mutgroup.add_argument(
        '-cV', '--createvuln', help="Create a vulnerability", action='store_true')

    mutgroup.add_argument(
        '-sN', '--scannmap', help="Perform nmap scan",
        metavar="NMAPOPTIONS")  # NMAP SCAN

    parser.add_argument(
        '-nt', '--notitle',
        help='Surpresses column titles to make output suitable for scripts',
        action='store_true')
    parser.add_argument(
        '-nT', '--notable', help="Remove Table formatting"
        " and output as CSV", action='store_true')

    parser.add_argument(
        '-N', '--networkid', help="Network ID")
    parser.add_argument(
        '-sH', '--secinthost', help="Secint HostID")

    parser.add_argument(
        '-hR', '--root', help="root", type=int)
    parser.add_argument(
        '-hP', '--pwned', help="pwned", type=int)
    parser.add_argument(
        '-hS', '--status', help="Status", type=int)
    parser.add_argument(
        '-hN', '--hostname', help="Hostname")
    parser.add_argument(
        '-hOS', '--hostos', help="HostOS")

    parser.add_argument(
        '-U', '--username', help="Username")
    parser.add_argument(
        '-P', '--password', help="Password")
    parser.add_argument(
        '-iH', '--ishash', help="password is hashed",
        type=int)

    parser.add_argument(
        '-Hi', '--hostid', help="Host ID", type=int)
    parser.add_argument(
        '-Si', '--serviceid', help="Service ID", type=int )

    parser.add_argument(
        '-S', '--source', help="Source of a password or hash")

    parser.add_argument(
        '-sP', '--serviceproto', help="Service Proto",
        type=int)
    parser.add_argument(
        '-sp', '--serviceport', help="Service Port",
        type=int)

    parser.add_argument(
        '-nP', '--notpwned', help="Prevents pwn'd hosts from "
        "showing up", action='store_true')

    parser.add_argument(
        'filter', type=str, nargs='?', help='Filters output lists')
    args = parser.parse_args()

    data_handler = secintdata.DataHandler(APP_PATH)

    def multi_line_input(helloString, stringDelim):
        print helloString
        stringBuf = ""
        if stringDelim != None:
            for line in iter(raw_input, stringDelim):
                stringBuf = stringBuf + line
                pass
        return stringBuf

    if (args.listhosts):
        host_list = data_handler.get_hosts()
        secintdisplay.ListHosts(
            host_list, args.notable, args.notitle, 
            args.filter, args.notpwned)
    elif (args.scannmap is not None):
        nmap_handler = secintscans.NmapScan(data_handler)
        nmap_handler.run_scan(args.scannmap)
    elif (args.listnetworks):
        network_list = data_handler.get_networks()
        secintdisplay.ListNetworks(
            network_list, args.notable, args.notitle, args.filter)
    elif (args.listservices):
        host_list = data_handler.get_hosts()
        secintdisplay.ListServices(
            host_list, args.notable, args.notitle,
            args.filter, args.notpwned)
    elif (args.listscans):
        scan_list = data_handler.get_scans()
        secintdisplay.ListScans(
            scan_list, args.notable, args.notitle, args.filter)
    elif (args.listscannedhosts is not None):
        nmap_handler = secintscans.NmapScan(data_handler)
        nmap_handler.display_hosts(args.listscannedhosts,
            args.notable, args.notitle, args.filter)
    elif (args.listscannedservices is not None):
        nmap_handler = secintscans.NmapScan(data_handler)
        nmap_handler.display_services(args.listscannedservices,
            args.notable, args.notitle, args.filter)
    elif (args.promotehost is not None):
        nmap_handler = secintscans.NmapScan(data_handler)
        nmap_handler.promote_host(args.promotehost, args.networkid)
    elif (args.updatehost is not None):
        data_handler.update_host(args.updatehost, args.hostname, args.status, args.pwned, args.root)
    elif (args.promotenic is not None):
        nmap_handler = secintscans.NmapScan(data_handler)
        nmap_handler.promote_nic(args.promotehost, args.networkid, args.secinthost)
    elif (args.createnetwork):
        network_subnet = raw_input("Enter the subnet in ip/prefix format: ")
        sub_arr = network_subnet.split("/")
        network_ip = sub_arr[0]
        network_prefix = sub_arr[1]
        network_desc = multi_line_input("Enter a description. Enter (!) to finish: ", "!")
        data_handler.add_network(network_ip, network_prefix, network_desc)
    elif (args.createnic is not None):
        if args.networkid is not None:
            network_id = args.networkid
        else:
            network_id = raw_input("Enter a network id: ")
        nic_ip = raw_input("Please enter the IP address: ")
        nic_prefix = raw_input("Please enter the prefix: ")
        data_handler.create_nic(args.createnic, network_id, nic_ip, nic_prefix)
    elif (args.hostdetails is not None):
        host_list = data_handler.get_hosts()
        secintdisplay.DetailHost(host_list, args.hostdetails)
    elif (args.createservice is not None):
        if (args.serviceproto is not None):
            service_proto = args.serviceproto
        else:
            service_proto = raw_input("Enter the ip proto num: ")
        if (args.serviceport is not None):
            service_port = args.serviceport
        else:
            service_port = raw_input("Enter the port number: ")
        data_handler.create_service(args.createservice, service_proto, service_port)
    elif (args.createhost):
        if (args.hostname is not None):
            hostname = args.hostname
        else:
            hostname = raw_input("Enter a hostname: ")
        if (args.hostos is not None):
            hostos = args.hostos
        else:
            hostos = raw_input("Enter the OS: ")
        if (args.status is not None):
            hoststatus = args.status
        else:
            hoststatus = raw_input("Host status (1/0): ")
        if (args.pwned is not None):
            hostpwned = args.pwned
        else:
            hostpwned = raw_input("Host pwned (1/0): ")
        if (args.root is not None):
            hostroot = args.root
        else:
            hostroot = raw_input("Host root (1/0): ")
        data_handler.create_host(hostname, hostos, hoststatus, hostpwned, hostroot)
    elif(args.addcredential):
        if (args.username is not None or args.password is not None):
            if (args.username is not None):
                username = args.username
            else:
                username = ""
            if (args.password is not None):
                password = args.password
            else:
                password = ""
        if (args.ishash is not None):
            is_hash = 1
            hash_id = args.ishash
        else:
            is_hash = 0
            hash_id = 0
        ready_bool = True
        if (args.hostid is not None and args.serviceid is not None):
            print("Please select either hostid, serviceid, or nothing")
            ready_bool = False
        elif (args.hostid is not None):
            source_type = 1
            source_id = args.hostid
        elif (args.serviceid is not None):
            source_type = 2
            source_id = args.serviceid
        elif (args.serviceid is None and args.hostid is None):
            source_type = 0
            source_id = 0
        if (ready_bool is True):
            data_handler.add_credential(username, password, is_hash, hash_id, source_type, source_id)
    elif(args.listhashetypes):
        hashtype_list = data_handler.get_hash_types()
        secintdisplay.ListHashTypes(hashtype_list)
    elif(args.listcreds):
        cred_list = data_handler.get_creds()
        secintdisplay.ListCreds(cred_list, args.notable, args.notitle, args.filter)

if __name__ == "__main__":
    main()
