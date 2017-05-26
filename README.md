# nmap-crawler
Wraps around nmap commands and parses results into a csv file, developed for MS17-010 exploit (WannaCry)

Requires nmap and perl

Nmap should be at version 7.30 or higher for the MS17-010 script. 

Accepts subnet as the argument

If you have multiple subnets to run I suggest using a wrapper bash file or other shell script. I have added an example. Remmeber to set the execution flag:
chmod a+x ./scriptname.pl ./scriptname.sh

credit to the maker of this nmap script for the MS17-010 vulnerabiltiy check:
https://github.com/cldrn/nmap-nse-scripts/blob/master/scripts/smb-vuln-ms17-010.nse
