#!/usr/bin/python


import nmap
import subprocess
import os


class NmapScan():
    def __init__(self, data_handler):
        self.data_handler = data_handler

    def run_scan(self, options):
        pipe = subprocess.Popen(["./tools/nmapdb.pl", options],
                                                stdout=subprocess.PIPE)
        result = pipe.stdout.read()

    def get_hosts(self, scanid):
        host_handle = self.data_handler.get_data("SELECT * FROM"
            " SecintScan_NmapHosts WHERE ParentScan=" + str(scanid))
        return host_handle

    def get_host(self, hostid):
        host_handle = self.data_handler.get_data("SELECT * FROM"
            " SecintScan_NmapHosts WHERE HostID=" + str(hostid))
        return host_handle

    def get_services(self, hostid):
        service_handle = self.data_handler.get_data("SELECT * FROM"
        " SecintScan_NmapServices WHERE ParentHost=" + str(hostid))
        return service_handle

    def promote_host(self, scanhostid, networkid):
        host = self.data_handler.SecintHost()
        nic = self.data_handler.SecintNic()
        service_list = list()
        host_handle = self.get_host(scanhostid)
        host_row = host_handle.fetch_row()
        host.host_name = host_row[0][4]
        host.host_os = host_row[0][5]
        if host_row[0][3] == "up":
            host.host_status = 1
        else:
            host.host_status =0
        host.host_pwned = 0
        host.host_root = 0
        network_list = self.data_handler.get_networks()
        for tmp_net in network_list:
            if (tmp_net.network_id == networkid):
                network = tmp_net
        nic.nic_ip = host_row[0][1]
        nic.nic_prefix = tmp_net.network_prefix
        nic.network_id = tmp_net.network_id
        nic.network_ip = tmp_net.network_ip
        nic.network_desc = tmp_net.network_desc
        nic.network_prefix = tmp_net.network_prefix
        host.nic_list.append(nic)
        service_handle = self.get_services(host_row[0][0])
        while True:
            service_row = service_handle.fetch_row()
            if not service_row:
                break
            tmp_service = self.data_handler.SecintService()
            tmp_service.service_id = service_row[0][0]
            if service_row[0][1] == "tcp":
                tmp_service.service_proto = 6
            elif service_row[0][1] == "udp":
                tmp_service.service_proto = 17
            else:
                tmp_service.service_proto = 0
            tmp_service.service_port = service_row[0][2]
            tmp_service.service_name = service_row[0][3]
            tmp_service.service_product = service_row[0][6]
            tmp_service.service_version = service_row[0][7]
            service_list.append(tmp_service)
        self.data_handler.create_host_from_scan(host, nic, service_list)

    def display_hosts(self, scanid, notable, notitle, filter):
        if filter is None:
            filter = ''
        host_handle = self.get_hosts(scanid)
        template = "{0:3}|{1:15}|{2:6}|{3:10}|{4:30}"
        if not notitle:
            if not notable:
                print template.format("ID", "IP", "Status", "Name", "OS")
            else:
                print "ID\tHostIP\tHostStatus\tHostName\tHostOS"
        while True:
            host_row = host_handle.fetch_row()
            if not host_row:
                break
            grep_text = (host_row[0][0] + "\t" + host_row[0][1] + "\t" +
                host_row[0][3] + "\t" + host_row[0][4] + "\t" + host_row[0][5])
            if filter in grep_text:
                if notable:
                    print (host_row[0][0] + "\t" + host_row[0][1] + "\t" +
                            host_row[0][3] + "\t" + host_row[0][4] + "\t" +
                            host_row[0][5])
                else:
                    print template.format(host_row[0][0], host_row[0][1],
                        host_row[0][3], host_row[0][4], host_row[0][5])

    def display_services(self, scanid, notable, notitle, filter):
        if filter is None:
            filter = ''
            host_handle = self.get_hosts(scanid)
            template = "{0:15}|{1:25}|{2:8}|{3:8}|{4:8}|{5:15}|{6:45}|{7:35}"
            if not notitle:
                if not notable:
                    print template.format("IP", "HostName", "SvcID", "Proto",
                        "Port", "SvcName", "SvcProduct", "SvcVersion")
                else:
                    print ("IP\tHostName\tSvcID\tProto\tPort"
                                "\tSvcName\tSvcProduct\tSvcVersion")
            while True:
                host_row = host_handle.fetch_row()
                if not host_row:
                    break
                service_handle = self.get_services(host_row[0][0])
                while True:
                    service_row = service_handle.fetch_row()
                    if not service_row:
                        break
                    grep_text = (host_row[0][1] + "\t" + host_row[0][4] +
                        "\t" + service_row[0][0] + "\t" + service_row[0][1] +
                        "\t" + service_row[0][2] + "\t" + service_row[0][3] +
                        "\t" + service_row[0][6] + "\t" + service_row[0][7])
                    if filter in grep_text:
                        if notable:
                            print (host_row[0][1] + "\t" + host_row[0][4] +
                                "\t" + service_row[0][0] + "\t" +
                                service_row[0][1] + "\t" + service_row[0][2] +
                                "\t" + service_row[0][3] + "\t" +
                                service_row[0][6] + "\t" + service_row[0][7])
                        else:
                            print template.format(host_row[0][1],
                                host_row[0][4], service_row[0][0],
                                service_row[0][1], service_row[0][2],
                                service_row[0][3], service_row[0][6],
                                service_row[0][7])
