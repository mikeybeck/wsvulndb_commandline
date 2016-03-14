#!/usr/bin/python
import argparse
import sys
import subprocess
import requests
import json
from pprint import pprint
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def versiontuple(v):
    return tuple(map(int, (v.split("."))))

def runProcess(exe):    
    p = subprocess.Popen(exe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while(True):
      retcode = p.poll() #returns None while subprocess is running
      line = p.stdout.readline()
      yield line
      if(retcode is not None):
        break

def check_vuln_status(name,version,report,type):
	out=""
	vuln=0
	tag = {}
	tag["wordpresses"]="wordpress"
	tag["plugins"]="plugin"
	tag["themes"]="theme"
	r=requests.get("https://wpvulndb.com/api/v1/"+type+"/" + name)
	#print "https://wpvulndb.com/api/v1/"+type+"/" + name
	if r.status_code == 404:
		if not report:
			#print "(404)"
			#print "https://wpvulndb.com/api/v1/"+type+"/" + name
			out+= bcolors.OKGREEN + "[+]  "+ tag[type].capitalize() +" : " + name.capitalize() + " : Doesn't have any Reported Security Issue " + bcolors.ENDC
	else:
		data = json.loads(r.text)
		for x in data[tag[type]]["vulnerabilities"]:
			#print "Is vulnerable"
			#return str(x)
			if x.has_key("fixed_in"):
				#print "version: " + version 
				#print "fixed in: " + str(versiontuple(x["fixed_in"]))
				#print "versiontuple: " + str(versiontuple(version))
				if versiontuple(x["fixed_in"]) > versiontuple(version):
					print "Fixed.."
					if tag[type] == "wordpress":
						name="core"
					if vuln==0:
						out = bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name.capitalize() + " : " + version.rstrip()  + " : is Vulnerable to " + x["title"] + bcolors.ENDC + bcolors.OKGREEN + " Fixed in  Version " + x["fixed_in"] + bcolors.ENDC
						vuln = vuln + 1
					else:
						out+= "\n" + bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name.capitalize() + " : " + version.rstrip()  + " : is Vulnerable to " + x["title"] + bcolors.ENDC + bcolors.OKGREEN +" Fixed in Version " + x["fixed_in"] + bcolors.ENDC
					vuln = vuln + 1
				else:
					if vuln == 0:
						if not report:
							out = bcolors.OKGREEN + "[+]  " + tag[type].capitalize() + " : " + name.capitalize() + " : Doesn't have any Reported Security Issue " + bcolors.ENDC
						else:
							#print "-------------------1----------------"
							out = ""
						# vuln=0
			else:
				if vuln == 0:
					out=bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name.capitalize() + " : " + version.rstrip()  + " : is Vulnerable to : " + x["title"] + bcolors.ENDC
				else:
					out+=bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name.capitalize() + " : " + version.rstrip()  + " : is Vulnerable to : " + x["title"] + bcolors.ENDC
				vuln = vuln + 1
	return out

def cmd_exists(cmd):
    return subprocess.call("type " + cmd, shell=True, 
        stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


def main(argv):
	desc="""This program is used to run a quick wordpress scan via wpscan api. This command depends on wordshell"""
	epilog="""Credit (C) Anant Shrivastava http://anantshri.info - original code.  With modifications by mikeybeck"""
	parser = argparse.ArgumentParser(description=desc,epilog=epilog)
	parser.add_argument("--site",help="Provide site",dest='site',required=True)
	parser.add_argument("--vulnonly",help="Only List vulnerable Items",action="store_true")
	if not cmd_exists("wordshell"):
		print "Wordshell needs to be in path as executable named as wordshell"
		print "Visit http://wordshell.net to purchase"
		exit()
	x=parser.parse_args()
	wshellsite=x.site
	report=x.vulnonly

	
	#runProcess(("wordshell "+wshellsite+" --list").split())
	# Check Core Issues
	cmd="wordshell " + wshellsite + " --list --core"
	xinp=[]
	for line in runProcess(cmd.split()):
		if line != "":
			#if line.strip() != "name,version":
			line = ' '.join(line.split()).split(" ")[3]
			xinp.append(line)
			print "Wordpress version: " + line

	for x in xinp:
		y=x.replace(".","").strip()
		# Hacked code here version is sent instead of plugin name and plug name is marked as blank
		x = x[4:].replace(" ", "")
		out=check_vuln_status(y,x,report,"wordpresses")
		if out.strip() is not "":
			print out.strip()
	

	# Check Plugin Issues
	cmd="wordshell " + wshellsite + " --list"

	xinp=[]
	for line in runProcess(cmd.split()):
		if line != "":
			#if line.strip() != "name,version":
			xinp.append(line)
			print line
	for x in xinp:
		y = x.strip(wshellsite).replace(".php", "")
		#y = y.split("    ")
		#print y.strip()
		
		y = y.split(wshellsite,1)[1]
		#yArr = y.split(" ")
		name2 = y.split(" ")[2].replace(" ", "")
		name = "".join(name2.split())
		#if "." in name:
		#	name = name.split(".")[0]
		version = y.split(name2)[1].replace("(i)", "").replace("(-)", "").strip().split(" ")[0]		#print y.split(name)
		version = "".join(version.split())
		#y = y.strip()
		#print y.strip()
		#print y.replace(" ", "")
		name = name[6:]
		version = version[4:]

		print ""
		print name + " " + version
		#print "simple-ads-manager" + " " + "2.9.4.116"

		#delchars = ''.join(c for c in map(chr, range(256)) if not c.isalnum())
		#name = name.translate(None, delchars)
		#version = version.translate(None, delchars)

		#import re
		#name = re.sub(r'\W+', '', name)
		#version = re.sub(r'\W+', '', version)

		#f = open('workfile.txt', 'r+')
		#f.write(name + " " + version)
		#f.write("\r\n")
		#f.write("simple-ads-manager" + " " + "2.9.4.116")
		#with open("test.txt", "a") as myfile:
		#    myfile.write(name + " " + version + "\r\n")
		out=check_vuln_status(name,version,report,"plugins")
		if out.strip() is not "":
			print out.strip()

	'''

	for line in runProcess(cmd.split()):
		print 1.5
		if line != "":
			xinp.append(line)
			print 1.7
			print line


	print 2
	for x in xinp:
		print 3
		y=x.replace(".","").strip()
		print 3.5
		print y
		# Hacked code here version is sent instead of plugin name and plug name is marked as blank
		out=check_vuln_status(y,x.strip(),report,"wordpresses")
		print 3.7
		if out.strip() is not "":
			print out.strip()
			print 4
	cmd="wordshell --site=" + wshellsite + " theme list --format=csv --fields=name,version"
	xinp=[]
	for line in runProcess(cmd.split()):
		if line != "":
			if line.strip() != "name,version":
				xinp.append(line)
	for x in xinp:
		y=x.split(",")
		out=check_vuln_status(y[0],y[1],report,"themes")
		if out.strip() is not "":
			print out.strip()
	cmd="wp --path=" + wpbase + " plugin list --format=csv --fields=name,version"
	xinp=[]
	for line in runProcess(cmd.split()):
		if line != "":
			if line.strip() != "name,version":
				xinp.append(line)
	for x in xinp:
		y=x.split(",")
		out=check_vuln_status(y[0],y[1],report,"plugins")
		if out.strip() is not "":
			print out.strip()
	'''


if __name__ == "__main__":
   main(sys.argv[1:])