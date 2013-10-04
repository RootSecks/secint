#!/usr/bin/python


class ansicolors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PINK = '\033[95m'
    ENDC = '\033[0m'


class ListScans():
    def __init__(self, scan_list, notable, notitle, filter):
        if scan_list is not None:
            if filter is None:
                filter = ''
            if not notable:
                template = "{0:3}|{1:4}|{2:20}|{3:10}|{4:20}"
            if not notitle:
                if notable:
                    print("ID\tType\tTime\tDuration\tOptions")
                else:
                    print template.format("ID", "Type", "Time",
                        "Duration", "Options")
            for scan in scan_list:
                grep_text = (scan.scan_id + "\t" + scan.scan_type + "\t" +
                    scan.scan_time + "\t" + scan.scan_duration +
                    "\t" + scan.scan_options)
                if filter in grep_text:
                    if (notable):
                        print(scan.scan_id + "\t" + scan.scan_type + "\t" +
                            scan.scan_time + "\t" + scan.scan_duration +
                            "\t" + scan.scan_options)
                    else:
                        print template.format(scan.scan_id, scan.scan_type,
                            scan.scan_time, scan.scan_duration,
                            scan.scan_options)


class ListServices():
    """ListServices class

    Class that displays the services

    """
    def __init__(self, host_list, notable, notitle, filter):
        if host_list is not None:
            if filter is None:
                filter = ''
            if not notable:
                template = "{0:3}|{1:15}|{2:5}|{3:6}|{4:15}|{5:20}"
            if not notitle:
                if notable:
                    print("ID\tIP\tHost\t"
                            "Proto\tPort\t"
                            "Product\tVersion")
                else:
                    print template.format("ID", "IP",
                                                        "Proto", "Port",
                                                        "Product", "Version")
            for host in host_list:
                for nic in host.nic_list:
                    for service in nic.service_list:
                        grep_text = (service.service_id + "\t" + nic.nic_ip +
                            "\t" + service.service_proto + "\t" +
                            service.service_port + "\t" +
                            service.service_product + "\t" +
                            service.service_version)
                        if filter in grep_text:
                            if (notable):
                                print(service.service_id + "\t" + nic.nic_ip +
                                        "\t" + service.service_proto + "\t" +
                                        service.service_port + "\t" +
                                        service.service_product + "\t" +
                                        service.service_version)
                            else:
                                print template.format(service.service_id,
                                    nic.nic_ip, service.service_proto,
                                    service.service_port,
                                    service.service_product,
                                    service.service_version)


class ListNetworks():
    """ListNetworks class

    Class that displays the networks

    """
    def __init__(self, network_list, notable, notitle, filter):
        if network_list is not None:
            if filter is None:
                filter = ''
            if not notable:
                template = "{0:3}|{1:15}|{2:10}|{3:20}"
            if not notitle:
                if notable:
                    print("NetworkID\tNetworkIP\t"
                                "NetworkPrefix\tNetworkDesc")
                else:
                    print template.format("ID", "IP", "Prefix", "Description")
            for network in network_list:
                greptext = (network.network_id + "\t" + network.network_ip +
                                    "\t" + network.network_prefix + "\t" +
                                    "\t" + network.network_desc)
                if filter in greptext:
                    if (notable):
                        print (network.network_id + "\t" + network.network_ip +
                                    "\t" + network.network_prefix + "\t" +
                                    "\t" + network.network_desc)
                    else:
                        print template.format(network.network_id,
                            network.network_ip,
                            network.network_prefix,
                            network.network_desc)


class ListHosts():
    """ListHosts class

    Class that displays the hosts

    """
    def __init__(self, host_list, notable, notitle, filter):
        if host_list is not None:
            if filter is None:
                filter = ''
            if not notable:
                template = "{0:3}|{1:23}|{2:3}|{3:3}|{4:3}|{5:15}"
            if not notitle:
                if notable:
                    print ("HostID\tHostName\t"
                                "HostStatus\tHostPwned\tHostRoot\tHostOS")
                else:
                    print template.format("ID", "Name", "STS",
                                                        "PWN", "ROT", "OS")
            for host in host_list:
                greptext = (host.host_id + "\t\t" + host.host_name +
                    "\t" + host.host_status + "\t\t" + host.host_pwned +
                    "\t\t" + host.host_root + "\t\t" + host.host_os)
                if filter in greptext:
                    if (host.host_status == "1"):
                        host.host_status = (ansicolors.GREEN +
                                                    "[+]" + ansicolors.ENDC)
                    else:
                        host.host_status = (ansicolors.RED +
                                                    "[-]" + ansicolors.ENDC)
                    if (host.host_root == "1"):
                        host.host_root = (ansicolors.GREEN +
                                                "[+]" + ansicolors.ENDC)
                    else:
                        host.host_root = (ansicolors.RED +
                                                "[-]" + ansicolors.ENDC)
                    if (host.host_pwned == "1"):
                        host.host_pwned = (ansicolors.GREEN +
                                                    "[+]" + ansicolors.ENDC)
                    else:
                        host.host_pwned = (ansicolors.RED +
                                                    "[-]" + ansicolors.ENDC)
                    if (notable):
                        print (host.host_id + "\t" + host.host_name + "\t" +
                                host.host_status + "\t\t" + host.host_pwned +
                                "\t\t" + host.host_root + host.host_os + "\t")
                    else:
                        print template.format(host.host_id, host.host_name,
                            host.host_status, host.host_pwned,
                            host.host_root, host.host_os)
