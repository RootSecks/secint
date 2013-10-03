#!/usr/bin/python


from secintobjects import *
import _mysql


class DataHandler():
    """ DataHandler Class

    Moves data from secint to the secint database and back again

    """
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
                tmp_nic.nic_mask = nic_row[0][4]
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
                    tmp_service.service_id = row[0][0]
                    tmp_service.service_proto = row[0][2]
                    tmp_service.service_port = row[0][3]
                    tmp_service.service_name = row[0][4]
                    tmp_service.service_product = row[0][5]
                    tmp_service.service_version = row[0][6]
                    service_list.append(tmp_service)
                tmp_nic.service_list = service_list
                nic_list.append(tmp_nic)
            tmp_host.nic_list = nic_list
            host_list.append(tmp_host)
        return host_list
