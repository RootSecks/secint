usage: secint [-h] [-lS] [-lSc] [-lH] [-nT] [-rQ] [-oT] [-cV] [-lV] [-sN]
              [-sS SELECTSCAN] [-d]
              [filter]

positional arguments:
  filter                Filters returned results based on ip address or
                        service

optional arguments:
  -h, --help            show this help message and exit
  -lS, --services       Display a list of services
  -lSc, --scans         Display all the scans
  -lH, --hosts          Display a list of hosts
  -nT, --notitle        Surpresses column titles to make output suitable for
                        scripts
  -rQ, --rawquery       Run a raw query against the database
  -oT, --outtable       Output as pretty table
  -cV, --createvector   Create a new attack vector record
  -lV, --listvectors    List all vectors
  -sN, --scannmap       Run an nmap scan
  -sS SELECTSCAN, --selectscan SELECTSCAN
                        Return objects from a specific scan
  -d, --debug           Enable debug messages



Usage example: 
Step 1 - Scan a network:
	./secint -sN '-A 127.0.0.1'
Step 2 - View Stored Info from Scan:
	./secint -lH -oT
	./secint -lS -oT
Step 3 - Identify vulnerable services, and create a vector:
	./sectint -cV "1|www.exploit-db.com/blah"
Step 4 - View all the sweet attacl vectors you found:
	./sectint -lV
