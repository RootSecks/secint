usage: secint [-h] [-lS] [-lSc] [-lH] [-lC] [-nT] [-rQ] [-aC] [-oT] [-cV]
              [-lV] [-sN] [-sS SELECTSCAN] [-d]
              [filter] [serviceid]

positional arguments:
  filter                Filters returned results
  serviceid             ID of the service this vector exploits

optional arguments:
  -h, --help            show this help message and exit
  -lS, --services       Display a list of services
  -lSc, --scans         Display all the scans
  -lH, --hosts          Display a list of hosts
  -lC, --credentials    Display list of credentials
  -nT, --notitle        Surpresses column titles to make output suitable for
                        scripts
  -rQ, --rawquery       Run a raw query against the database
  -aC, --addcredential  Add a credential
  -oT, --outtable       Output as pretty table
  -cV, --createvector   Create a new attack vector record
  -lV, --listvectors    List all vectors
  -sN, --scannmap       Run an nmap scan
  -sS SELECTSCAN, --selectscan SELECTSCAN
                        Return objects from a specific scan
  -d, --debug           Enable debug messages



Usage example: <br>
Step 1 - Scan a network: <br>
	./secint -sN '-A 127.0.0.1' <br>
Step 2 - View Stored Info from Scan: <br>
	./secint -lH -oT <br>
	./secint -lS -oT <br>
Step 3 - Identify vulnerable services, and create a vector:<br>
	./sectint -cV "1|www.exploit-db.com/blah" <br>
Step 4 - View all the sweet attacl vectors you found: <br>
	./sectint -lV <br>
