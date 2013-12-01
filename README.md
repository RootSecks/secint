usage: secint.py [-h] <br>
                 (-lH | -lN | -lS | -hD HOSTDETAILS | -lSc | -lSh SCANID | -lSs SCANID | -lC | -pH HOSTID | -uH HOSTID | -pN HOSTID | -cH | -cNi HOSTID | -cS NICID | -aC | -lHt | -cN | -cV | -sN NMAPOPTIONS)<br>
                 [-nt] [-nT] [-N NETWORKID] [-sH SECINTHOST] [-hR ROOT]<br>
                 [-hP PWNED] [-hS STATUS] [-hN HOSTNAME] [-hOS HOSTOS]<br>
                 [-U USERNAME] [-P PASSWORD] [-iH ISHASH] [-Hi HOSTID]<br>
                 [-Si SERVICEID] [-S SOURCE] [-sP SERVICEPROTO]<br>
                 [-sp SERVICEPORT] [-nP] [-nO NMAPOPTIONS]<br>
                 [filter]<br>
<br>
Security Intellegence Framework<br>
<br>
positional arguments:<br>
  filter                Filters output lists<br>
<br>
optional arguments:<br>
  -h, --help            show this help message and exit<br>
  -lH, --listhosts      List host<br>
  -lN, --listnetworks   List Networks<br>
  -lS, --listservices   List Services<br>
  -hD HOSTDETAILS, --hostdetails HOSTDETAILS
                        Show detailed host info<br>
  -lSc, --listscans     List scans
  -lSh SCANID, --listscannedhosts SCANID
                        List scanned hosts<br>
  -lSs SCANID, --listscannedservices SCANID
                        List scanned services<br>
  -lC, --listcreds      List creds<br>
  -pH HOSTID, --promotehost HOSTID
                        Promote host froma scan to a secint host<br>
  -uH HOSTID, --updatehost HOSTID
                        Update<br>
  -pN HOSTID, --promotenic HOSTID
                        Promote a nic to an existing host from a scanned host<br>
  -cH, --createhost     Create a host<br>
  -cNi HOSTID, --createnic HOSTID
                        Create a nic<br>
  -cS NICID, --createservice NICID
                        Create a service<br>
  -aC, --addcredential  Add credentials<br>
  -lHt, --listhashetypes
                        List hash types<br>
  -cN, --createnetwork  Create network<br>
  -cV, --createvuln     Create a vulnerability<br>
  -sN NMAPOPTIONS, --scannmap NMAPOPTIONS
                        Perform nmap scan<br>
  -nt, --notitle        Surpresses column titles to make output suitable for
                        scripts<br>
  -nT, --notable        Remove Table formatting and output as CSV<br>
  -N NETWORKID, --networkid NETWORKID
                        Network ID<br>
  -sH SECINTHOST, --secinthost SECINTHOST
                        Secint HostID<br>
  -hR ROOT, --root ROOT
                        root<br>
  -hP PWNED, --pwned PWNED
                        pwned<br>
  -hS STATUS, --status STATUS
                        Status<br>
  -hN HOSTNAME, --hostname HOSTNAME
                        Hostname<br>
  -hOS HOSTOS, --hostos HOSTOS
                        HostOS<br>
  -U USERNAME, --username USERNAME
                        Username<br>
  -P PASSWORD, --password PASSWORD
                        Password<br>
  -iH ISHASH, --ishash ISHASH
                        password is hashed<br>
  -Hi HOSTID, --hostid HOSTID
                        Host ID<br>
  -Si SERVICEID, --serviceid SERVICEID
                        Service ID<br>
  -S SOURCE, --source SOURCE
                        Source of a password or hash<br>
  -sP SERVICEPROTO, --serviceproto SERVICEPROTO
                        Service Proto<br>
  -sp SERVICEPORT, --serviceport SERVICEPORT
                        Service Port<br>
  -nP, --notpwned       Prevents pwn'd hosts from showing up<br>
  -nO NMAPOPTIONS, --nmapoptions NMAPOPTIONS
                        Additional flags to useWhen running nmap scans<br>

