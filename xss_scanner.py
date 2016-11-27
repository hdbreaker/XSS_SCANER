import os
import argparse
import subprocess
from scan import Scanner

parser = argparse.ArgumentParser()
parser.add_argument('-url', help='Host to Scan')
parser.add_argument('-threads', help='Number of Threads', default="0")
parser.add_argument('-cookies', help='Cookies file', default=None)
parser.add_argument('-dbclear', help='Clean the database', action='store_true')
parser.add_argument('-dockerize', help='Build Docker Image', action='store_true')
parser.add_argument('-show', help='Show stored results', action='store_true')
parser.add_argument(
    '-ltest', help='Start simple local test [Database will be erased]', action='store_true')

args = parser.parse_args()

if(args.dockerize):
	if(os.getuid() == 0):
		cmd = 'docker build -t xss_scanner .'
		subprocess.call(cmd.split())
		print "[+] Builing Done"
		print "[+] Please run: sudo docker run xss_scanner"
	else:
		print "[-] Must be root to build docker images!!!"
		print "[-] Please try with: sudo python xss_scanner.py -dockerize"
else:
	if(args.url or args.dbclear or args.show or args.ltest):
	    scanner = Scanner(args.url, args.threads, args.cookies,
	                      args.show, args.dbclear, args.ltest)
	    scanner.show_data()
	else:
	    parser.print_help()
	    print "\nExample:"
	    print "python xss_scanner.py -u https://google-gruyere.appspot.com/236398396161/snippets.gtl -t 30 -c cookies.txt"
	    print "python xss_scanner.py -dockerize"
	    print "python xss_scanner.py -ltest"
	    print "python xss_scanner.py -show"
	     
	   
