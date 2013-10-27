#!/usr/bin/python


class SecintScan():
    def __init__(self):
        self.scan_id = None
        self.scan_type = None
        self.scan_time = None
        self.scan_duration = None
        self.scan_options = None

class HashType():
    def __init__(self):
        self.hash_id = None
        self.hash_name = None

class SecintCred():
    def __init__(self):
        self.cred_id = None
        self.cred_user = None
        self.cred_pass = None
        self.cred_ishash = None
        self.cred_hashtype = None
        self.cred_sourcetype = None
        self.cred_sourceid = None

class SecintHost():
    """SecintHost Class

    Contains methods and variables that define the "host" object.
    This represents servers, computers, routers, and other devices
    on a network.

    DB Table:
    +------------+--------------+------+-----+---------+----------------+
    | Field      | Type         | Null | Key | Default | Extra          |
    +------------+--------------+------+-----+---------+----------------+
    | HostID     | int(11)      | NO   | PRI | NULL    | auto_increment |
    | HostName   | varchar(255) | YES  |     | NULL    |                |
    | HostOS     | text         | YES  |     | NULL    |                |
    | HostStatus | tinyint(1)   | YES  |     | NULL    |                |
    | HostPwned  | tinyint(1)   | YES  |     | NULL    |                |
    | HostRoot   | tinyint(1)   | YES  |     | NULL    |                |
    +------------+--------------+------+-----+---------+----------------+

    """
    def __init__(self):
        self.host_id = None
        self.host_name = None
        self.host_os = None
        self.host_status = None
        self.host_pwned = None
        self.host_root = None
        self.nic_list = list()

    def get_nics():
        return self.nic_list


class SecintNetwork():
    def __init__(self):
        self.network_id = None
        self.network_ip = None
        self.network_prefix = None
        self.network_desc = None


class SecintNic(SecintNetwork):
    """SecintNic Class

    Contains methods and variables that define
    the "NIC" object. This represent the network
    interfaces on a host.

    """
    def __init__(self):
        SecintNetwork.__init__(self)
        self.nic_id = None
        self.nic_ip = None
        self.nic_prefix = None
        self.service_list = list()

    def get_services():
        return self.service_list


class SecintService(SecintNic):
    def __init__(self):
        SecintNic.__init__(self)
        self.service_id = None
        self.service_proto = None
        self.service_port = None
        self.service_name = None
        self.service_product = None
        self.service_version = None
