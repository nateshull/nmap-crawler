#! /usr/bin/perl
#runs command and parses the output from the command to
#generate a csv file of results for easier consuption
#An argument is used to pass the subnet on to the command
use strict;
use Getopt::Std;
my $subnet = @ARGV[0];
#turn on debug to see all activities! 0 = off, 1 = on, 2 = verbose
my $debug = 0;  


#this should not change..
my $nmaphostline = "Nmap scan report for ";

#ms17-010 keyword:
my $nmapreskeyphrase = "VULNERABLE";

#nmap command options include the dashes
my $nmapscantype = "-sC";
my $nmapport = "-p445";
my $nmapoptions = "--open --max-hostgroup 3";
my $nmapscript = "--script smb-vuln-ms17-010.nse";

#show all hosts or just ones that match: 1 to showall, 0 to hide.
my $showall = 1;

#what to output for the result column
my $resultmatchphrase = "vulnerable";
my $resultotherphrase = "patched or n/a";

#fix file name output if there is a subnet slash
my $subnetadj = $subnet;
$subnetadj =~ s#/#msk#g;
my $filename = "netscan-$subnetadj.csv";

#nmap base command, adds scan target from
my $nmapcmd = "nmap $nmapscantype $nmapport $nmapoptions $nmapscript ";
if ($debug) {print "!!! $nmapcmd \n";}

print "Starting to Scan $subnet\n";

my @nmapout = `$nmapcmd$subnet`;
chomp @nmapout;

#start of csv file
my $csvbuild = "\"Host\",\"Result\"\n";
my $host = "";

#parse lines and build csv output
foreach my $line (@nmapout) {
	#look for the host line keyword
	if (index($line,$nmaphostline) > -1) {
		if ($host ne "" && $showall == 1) {
			$csvbuild .= "\"$host\",\"$resultotherphrase\"\n";
		}
		$host = $line;
		$host =~ s/$nmaphostline//g;
		if ($debug) {print "!!! new host found: $host \n";}
	}

	#match the result lines
	if (index($line,$nmapreskeyphrase) > -1 && $host ne "") {
		$csvbuild .= "\"$host\",\"$resultmatchphrase\"\n";
		if ($debug) {print "!!! result matched: $host \n";}
		if ($debug == 2) {print "result matched: $line \n";}
		$host = "";		
	} else {
		if ($debug == 2) {print "result not matched: $line \n";}	
	}
}

#add last line
if ($host ne "" && $showall == 1) {
	$csvbuild .= "\"$host\",\"$resultotherphrase\"\n";
}
open(my $fh,'>',$filename);
print $fh $csvbuild;
print "finished scanning $subnet \n"
