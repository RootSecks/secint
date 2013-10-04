#!/usr/bin/python

from secintobjects import *
import _mysql


class DataHandler():
    """ DataHandler Class

    Moves data from secint to the secint database and back again

    """
    from secintobjects import *
    def __init__(self):
        self.db_name = None
        self.db_user = None
        self.db_pass = None
        self.db_host = None
        conf_handle = open('secint.conf', 'r')
        for conf_line in conf_handle:
            conf_line = conf_line.strip('\n')
            conf_array = conf_line.split('=')
            if (conf_array[0] == "database"):
                self.db_name = conf_array[1]
            elif (conf_array[0] == "user"):
                self.db_user = conf_array[1]
            elif (conf_array[0] == "password"):
                self.db_pass = conf_array[1]
            elif (conf_array[0] == "host"):
                self.db_host = conf_array[1]

    def init_db_con(self):
        """_init_db_con function

        Create a connection to the mysql DB and return the handle

        """
        db_handle = _mysql.connect(self.db_host, self.db_user,
                                    self.db_pass, self.db_name)
        return db_handle

    def create_host_from_scan(self, host, nic, service_list):
        add_host_handle = self.init_db_con()
        add_host_query = ("INSERT INTO SecintHosts (HostName, "
                                        "HostOS, HostStatus, HostPwned, HostRoot)"
                                        " VALUES (\"" + host.host_name + "\", \"" +
                                        host.host_os + "\", " + str(host.host_status) + 
                                        ", " + str(host.host_pwned) + ", " + str(host.host_root) +
                                        ")")
        add_host_handle.query(add_host_query)
        add_nic_handle = ("INSERT INTO SecintNics (HostID, NetworkID, NicIP, NicPrefix) "
                                        "VALUES (LAST_INSERT_ID(), " + nic.network_id + ", \"" +
                                        nic.network_ip + "\", \"" + nic.network_prefix + "\")")
        add_host_handle.query(add_nic_handle)
        get_nic_id = "SELECT LAST_INSERT_ID()"
        add_host_handle.query(get_nic_id)
        nic_handle = add_host_handle.use_result()
        nic_row = nic_handle.fetch_row()
        nic_id = nic_row[0][0]
        for service in service_list:
            service_db_handle = self.init_db_con()
            add_service = ("INSERT INTO SecintServices (nicID, ServiceProto, ServicePort,"
                                    " ServiceName, ServiceProduct, ServiceVersion) VALUES (" +
                                    nic_id + ", " + str(service.service_proto) + ", " + str(service.service_port) +
                                    ", \"" + service.service_name + "\", \"" + service.service_product +
                                    "\", \"" + service.service_version + "\")")
            service_db_handle.query(add_service)

    def get_data(self, query):
        data_db_handle = self.init_db_con()
        data_db_handle.query(query)
        return data_db_handle.use_result()

    def get_scans(self):
        scan_db_handle = self.init_db_con()
        get_scans_query = "SELECT * FROM SecintScans"
        scan_db_handle.query(get_scans_query)
        scans_handle = scan_db_handle.use_result()
        scan_list = list()
        while True:
            scan_row = scans_handle.fetch_row()
            if not scan_row:
                break
            tmp_scan = SecintScan()
            tmp_scan.scan_id = scan_row[0][0]
            tmp_scan.scan_type = scan_row[0][1]
            tmp_scan.scan_time = scan_row[0][2]
            tmp_scan.scan_duration = scan_row[0][3]
            tmp_scan.scan_options = scan_row[0][4]
            scan_list.append(tmp_scan)
        return scan_list

    def get_networks(self):
        network_db_handle = self.init_db_con()
        get_networks_query = "SELECT * FROM SecintNetworks"
        network_db_handle.query(get_networks_query)
        networks_handle = network_db_handle.use_result()
        network_list = list()
        while True:
            network_row = networks_handle.fetch_row()
            if not network_row:
                break
            tmp_network = SecintNetwork()
            tmp_network.network_id = network_row[0][0]
            tmp_network.network_ip = network_row[0][1]
            tmp_network.network_prefix = network_row[0][2]
            tmp_network.network_desc = network_row[0][3]
            network_list.append(tmp_network)
        return network_list

    def get_hosts(self):
        host_db_handle = self.init_db_con()
        get_hosts_query = "SELECT * FROM SecintHosts"
        host_db_handle.query(get_hosts_query)
        hosts_handle = host_db_handle.use_result()
        host_list = list()  # Create a list to hold all the hosts
        while True:
            host_row = hosts_handle.fetch_row()
            if not host_row:
                break
            tmp_host = SecintHost()
            tmp_host.host_id = host_row[0][0]
            tmp_host.host_name = host_row[0][1]
            tmp_host.host_os = host_row[0][2]
            tmp_host.host_status = host_row[0][3]
            tmp_host.host_pwned = host_row[0][4]
            tmp_host.host_root = host_row[0][5]
            nic_db_handle = self.init_db_con()
            get_nics_query = ("SELECT * FROM SecintNics WHERE HostID="
                                        + tmp_host.host_id)
            nic_db_handle.query(get_nics_query)
            nics_handle = nic_db_handle.use_result()
            nic_list = list()
            while True:
                nic_row = nics_handle.fetch_row()
                if not nic_row:
                    break
                tmp_nic = SecintNic()
                tmp_nic.nic_id = nic_row[0][0]
                tmp_nic.nic_ip = nic_row[0][3]
                tmp_nic.nic_prefix = nic_row[0][4]
                network_db_handle = self.init_db_con()
                get_networks_query = ("SELECT * FROM SecintNetworks "
                                                    "WHERE NetworkID="
                                                    + tmp_nic.nic_id)
                network_db_handle.query(get_networks_query)
                networks_handle = network_db_handle.use_result()
                network_row = networks_handle.fetch_row()
                tmp_nic.network_id = network_row[0][0]
                tmp_nic.network_ip = network_row[0][1]
                tmp_nic.network_prefix = network_row[0][2]
                tmp_nic.network_desc = network_row[0][3]
                service_db_handle = self.init_db_con()
                get_services_query = ("SELECT * FROM SecintServices WHERE"
                                                    " NicID=" + tmp_nic.nic_id)
                service_db_handle.query(get_services_query)
                services_handle = service_db_handle.use_result()
                service_list = list()
                while True:
                    service_row = services_handle.fetch_row()
                    if not service_row:
                        break
                    tmp_service = SecintService()
                    tmp_service.service_id = service_row[0][0]
                    tmp_service.service_proto = service_row[0][2]
                    tmp_service.service_port = service_row[0][3]
                    tmp_service.service_name = service_row[0][4]
                    tmp_service.service_product = service_row[0][5]
                    tmp_service.service_version = service_row[0][6]
                    service_list.append(tmp_service)
                tmp_nic.service_list = service_list
                nic_list.append(tmp_nic)
            tmp_host.nic_list = nic_list
            host_list.append(tmp_host)
        return host_list
