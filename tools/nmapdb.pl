#!/usr/bin/perl

use strict;
use warnings;

use Nmap::Parser;
use DBI();


my $np = new Nmap::Parser;


my $nmap_exe = "";
my $dbhost = " ";
my $dbname = " ";
my $dbuser = " ";
my $dbpass = " ";

open SECINTCONF, "../secint.conf" or die $!;

my @confline;

while (<SECINTCONF>) {

	chomp;
	
	if ($_ ne "") {
		
		my @confline = split('=', $_);
		
		if ($confline[0] eq "nmapbin") {
			$nmap_exe = $confline[1];		
		} elsif ($confline[0] eq "host") {
			$dbhost = $confline[1];
		} elsif ($confline[0] eq "database") {
			$dbname = $confline[1];
		} elsif ($confline[0] eq "user") {
			$dbuser = $confline[1];
		} elsif ($confline[0] eq "password") {
			$dbpass = $confline[1];
		}

	}

}

close SECINTCONF or die $!;;


if (!defined $dbpass) {
	$dbpass = '';
}

	

my $dbh = DBI->connect("DBI:mysql:database=$dbname;host=$dbhost",
                         "$dbuser", "$dbpass",
                         {'RaiseError' => 1});

my $allargs = shift;

$np->parsescan($nmap_exe, $allargs);

my $npsession = $np->get_session();

my $scantime = $npsession->finish_time() - $npsession->start_time();

$dbh->do("INSERT INTO SecintScans (ScanTime, ScanDuration, ScanOptions, ScanType) VALUES (NOW(), \"" . $scantime . "\", \"" . $allargs . "\", 1)");

my $lastscanid = $dbh->selectrow_array('SELECT LAST_INSERT_ID()');

for my $host ($np->all_hosts()){

	my $hoststatus = $host->status();
	my $hostaddr = $host->addr();
	my $hostname = $host->hostname();
	my $hostos = $host->os_sig();
	my $hostosname = $hostos->name();	
	
	if (!defined $hostos) {
		$hostos = '';
	}

	if (!defined $hostosname) {
		$hostosname = '';	
	}

	if (!defined $hostname) {
		$hostname = '';
	}

	$dbh->do("INSERT INTO SecintScan_NmapHosts (HostName, HostIP, ParentScan, HostStatus, HostOS) VALUES (\"" . $hostname . "\", \"" . $hostaddr . "\", " . $lastscanid . ", \"" . $hoststatus . "\", \"" . $hostosname . "\")");


	my $parenthostid = $dbh->selectrow_array('SELECT LAST_INSERT_ID()');

	for my $port ($host->tcp_ports('open')) {

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


		$dbh->do("INSERT INTO SecintScan_NmapServices (ServiceProto, ServicePort, ServiceName, ParentHost, ServiceFingerPrint, ServiceProduct, ServiceVersion) VALUES (\"" . $serviceproto . "\", \"" . $serviceport . "\", \"" . $servicename . "\", $parenthostid , \"" . $servicefingerprint . "\", \"" . $serviceproduct . "\", \"" . $serviceversion . "\")");
	
	}	

}


