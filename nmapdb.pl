#!/usr/bin/perl

use strict;
use warnings;

use Nmap::Parser;
use DBI();


my $np = new Nmap::Parser;
my $nmap_exe = '/usr/bin/nmap';
#my $scan_arg_default = '--dns-servers 192.168.17.221 -O -sV -p 21,22,23,69,25,53,80,161,443,445,1433,3306,3389,5900';
#my $scan_arg_default = '--dns-servers 192.168.17.221 -O -sV';
#my $scan_arg_default = '';
#my $scanrange = "192.168.17.200-254";





my $dbh = DBI->connect("DBI:mysql:database=sect;host=localhost",
                         "root", "",
                         {'RaiseError' => 1});

#my $scanarg = $scan_arg_default;


#my $allargs = $scanarg . " " . $scanrange;

my $allargs = shift;


print "Scanning with the following: \r\n";
print "nmap " . $allargs . "\r\n";	


$np->parsescan($nmap_exe, $allargs);

my $npsession = $np->get_session();

my $scantime = $npsession->finish_time() - $npsession->start_time();

print $scantime . "\r\n";

$dbh->do("INSERT INTO NmapScans (ScanTime, ScanDuration, ScanOptions) VALUES (NOW(), \"" . $scantime . "\", \"" . $allargs . "\")");

my $lastscanid = $dbh->selectrow_array('SELECT LAST_INSERT_ID()');

for my $host ($np->all_hosts()){

	print "Host: " . $host->addr() . " \r\n ";

	my $hoststatus = $host->status();
	my $hostaddr = $host->addr();
	my $hostname = $host->hostname();
	my $hostos = $host->os_sig();
	my $hostosname = $hostos->name();	

	$dbh->do("INSERT INTO NmapHosts (HostName, HostIP, ParentScan, HostStatus, HostOS) VALUES (\"" . $hostname . "\", \"" . $hostaddr . "\", " . $lastscanid . ", \"" . $hoststatus . "\", \"" . $hostosname . "\")");


	my $parenthostid = $dbh->selectrow_array('SELECT LAST_INSERT_ID()');

	print "Ports: \r\n";

	for my $port ($host->tcp_ports('open')) {

		print "\r\nPort: $port \r\n";

		my $serviceproto = $host->tcp_service($port)->proto();
		my $serviceport = $port;
		my $servicename = $host->tcp_service($port)->name();
		my $servicefingerprint = $host->tcp_service($port)->fingerprint();
		my $serviceproduct = $host->tcp_service($port)->product();
		my $serviceversion = $host->tcp_service($port)->version();

		if (index($allargs, "-sU") != -1) {

			$serviceproto = "udp";	

		} else {

			$serviceproto = "tcp";
		}

		if (!defined $servicefingerprint) {

			$servicefingerprint = " ";

		}

		if (!defined $serviceproduct) {

			$serviceproduct = " ";

		}

		if (!defined $serviceversion) {
			
			$serviceversion = " ";

		}


		print "Service Proto: " . $serviceproto;
		print "\r\nService FP: " . $servicefingerprint;
		print "\r\nService Product: " . $serviceproduct;
		print "\r\nService Version: " . $serviceversion;

		print "\r\n inserting service on port: " . $port . " into database under parent host: " . $parenthostid . "\r\n";		

		$dbh->do("INSERT INTO NmapServices (ServiceProto, ServicePort, ServiceName, ParentHost, ServiceFingerPrint, ServiceProduct, ServiceVersion) VALUES (\"" . $serviceproto . "\", \"" . $serviceport . "\", \"" . $servicename . "\", $parenthostid , \"" . $servicefingerprint . "\", \"" . $serviceproduct . "\", \"" . $serviceversion . "\")");
	
	}	

}


