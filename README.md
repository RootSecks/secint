usage: secint [-h] [-lS] [-lSc] [-lH] [-lC] [-nT] [-rQ] [-aC] [-oT] [-cV] [-lV] [-sN] [-sS SELECTSCAN] [-d] [filter] [serviceid]
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