usage: secint.py [-h] <br>
                 (-lH | -lN | -lS | -lSc | -lSh SCANID | -lSs SCANID | -pH HOSTID | -uH | -sN NMAPOPTIONS) <br>
                 [-nt] [-nT] [-N NETWORKID] <br>
                 [filter] <br>
<br>
Security Intellegence Framework <br>
<br>
positional arguments: <br>
  filter                Filters output lists <br>
<br>
optional arguments: <br>
  -h, --help            show this help message and exit <br>
  -lH, --listhosts      List host <br>
  -lN, --listnetworks   List Networks <br>
  -lS, --listservices   List Services <br>
  -lSc, --listscans     List scans <br>
  -lSh SCANID, --listscannedhosts SCANID List scanned hosts <br>
  -lSs SCANID, --listscannedservices SCANID List scanned services <br>
  -pH HOSTID, --promotehost HOSTID Promote host froma scan to a secint host <br>
  -uH, --updatehost     Update the status effects of a host <br>
  -sN NMAPOPTIONS, --scannmap NMAPOPTIONS Perform nmap scan <br>
  -nt, --notitle        Surpresses column titles to make output suitable for scripts <br>
  -nT, --notable        Remove Table formatting and output as CSV <br>
  -N NETWORKID, --networkid NETWORKID Network ID <br>

