usage: secint [-h] [-lS] [-lSc] [-lH] [-lC] [-nT] [-rQ] [-aC] [-oT] [-cV] [-lV] [-sN] [-sS SELECTSCAN] [-d] [-wI] [-wP WEBPORT] [filter] [serviceid]
<br>
positional arguments: <br>
  filter                Filters returned results <br>
  serviceid             ID of the service this vector exploits  <br>

optional arguments:  <br>
  -h, --help            show this help message and exit  <br>
  -lS, --services       Display a list of services  <br>
  -lSc, --scans         Display all the scans  <br>
  -lH, --hosts          Display a list of hosts  <br>
  -lC, --credentials    Display list of credentials  <br>
  -nT, --notitle        Surpresses column titles to make output suitable for scripts  <br>
  -rQ, --rawquery       Run a raw query against the database  <br>
  -aC, --addcredential  Add a credential  <br>
  -oT, --outtable       Output as pretty table  <br>
  -cV, --createvector   Create a new attack vector record  <br>
  -lV, --listvectors    List all vectors  <br>
  -sN, --scannmap       Run an nmap scan  <br>
  -sS SELECTSCAN, --selectscan SELECTSCAN Return objects from a specific scan  <br>
  -d, --debug           Enable debug messages  <br>
  -wI, --webinterface   Start Web Interface <br>
  -wP WEBPORT, --webport WEBPORT Define an option port for the web interface (Default 9191) <br>

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
  -lSh SCANID, --listscannedhosts SCANID <br>
                        List scanned hosts <br>
  -lSs SCANID, --listscannedservices SCANID <br>
                        List scanned services <br>
  -pH HOSTID, --promotehost HOSTID <br>
                        Promote host froma scan to a secint host <br>
  -uH, --updatehost     Update the status effects of a host <br>
  -sN NMAPOPTIONS, --scannmap NMAPOPTIONS <br>
                        Perform nmap scan <br>
  -nt, --notitle        Surpresses column titles to make output suitable for <br>
                        scripts <br>
  -nT, --notable        Remove Table formatting and output as CSV <br>
  -N NETWORKID, --networkid NETWORKID <br>
                        Network ID <br>

