#!/usr/bin/python
import argparse
import sys
import subprocess
import requests
import json
from pprint import pprint
import os
import time

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def update_progress(progress):
	if progress == 100:
		print '\r[{0}] {1}%'.format('#'*(progress/10), progress)
	else:
	    print '\r[{0}] {1}%'.format('#'*(progress/10), progress),

def versiontuple(v):
    return tuple(map(int, (v.split("."))))

def runProcess(exe):    
    progress = 0

    p = subprocess.Popen(exe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
    while(True):
      if (progress < 100):
          progress += 1
          update_progress(progress)
      retcode = p.poll() #returns None while subprocess is running
      line = p.stdout.readline()
      yield line
      if(retcode is not None):
      	update_progress(100)
        break

def check_vuln_status(name,version,report,type,debug):
	out=""
	vuln=0
	tag = {}
	tag["wordpresses"]="wordpress"
	tag["plugins"]="plugin"
	tag["themes"]="theme"
	r=requests.get("https://wpvulndb.com/api/v2/"+type+"/" + name)
	if debug:
		print "https://wpvulndb.com/api/v2/"+type+"/" + name
	if r.status_code == 404:
		if not report:
			if debug:
				print "(404)"
			out+= bcolors.OKGREEN + "[+]  "+ tag[type].capitalize() +" : " + name + " v" + version.rstrip() + " : No Reported Security Issues " + bcolors.ENDC
	else:
		data = json.loads(r.text)
		if debug: 
			print data
			print "version " + version

		#Sometimes case matters - try to prevent case problems
		if name.lower() in data:
			name = name.lower()

		if not data[name]["vulnerabilities"]:
			out = bcolors.OKGREEN + "[+]  " + tag[type].capitalize() + " : " + name + " v" + version.rstrip() + " : No Reported Security Issues " + bcolors.ENDC
		for x in data[name]["vulnerabilities"]:
			#print "Is vulnerable"
			#return str(x)
			if x.has_key("fixed_in"):
				#print "version: " + version 
				#print "fixed in: " + str(versiontuple(x["fixed_in"]))
				#print "versiontuple: " + str(versiontuple(version))
				if debug:
					print "versiontuple " + str(versiontuple(version))
					print "fixed in " + str(x["fixed_in"])
				if x["fixed_in"] and versiontuple(version) and versiontuple(x["fixed_in"]) > versiontuple(version):
					#print "Fixed.."
					if tag[type] == "wordpress":
						name="core"
					if vuln==0:
						out = bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name + " : " + version.rstrip()  + " : is Vulnerable to " + x["title"] + bcolors.ENDC + bcolors.OKGREEN + " Fixed in  Version " + x["fixed_in"] + bcolors.ENDC
						vuln = vuln + 1
					else:
						out+= "\n" + bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name + " : " + version.rstrip()  + " : is Vulnerable to " + x["title"] + bcolors.ENDC + bcolors.OKGREEN +" Fixed in Version " + x["fixed_in"] + bcolors.ENDC
					vuln = vuln + 1
				else:
					if vuln == 0 and x["fixed_in"] != None:
						if not report:
							out = bcolors.OKGREEN + "[+]  " + tag[type].capitalize() + " : " + name + " v" + version.rstrip() + " : No Reported Security Issues " + bcolors.ENDC
						else:
							if debug:
								print "Nothing..."
							#print "-------------------1----------------"
							out = ""
						# vuln=0
					else: # PLUGIN VULNERABLE AND FIX NOT AVAILBLE YET
						out = bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name + " : " + version.rstrip()  + " : is Vulnerable to " + x["title"] + " - NO FIX AVAILABLE YET" + bcolors.ENDC# + bcolors.OKGREEN + " Fixed in  Version " + x["fixed_in"] + bcolors.ENDC
			else:
				if vuln == 0:
					out=bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name + " : " + version.rstrip()  + " : is Vulnerable to : " + x["title"] + bcolors.ENDC
				else:
					out+=bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name + " : " + version.rstrip()  + " : is Vulnerable to : " + x["title"] + bcolors.ENDC
				vuln = vuln + 1
	return out

def cmd_exists(cmd):
    return subprocess.call("type " + cmd, shell=True, 
        stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0



def main(argv):
	desc="""This program is used to run a quick wordpress scan via wpscan api. This command depends on wordshell"""
	epilog="""Credit (C) Anant Shrivastava http://anantshri.info - original code.  With Wordshell compatibility modifications by mikeybeck"""
	parser = argparse.ArgumentParser(description=desc,epilog=epilog)
	parser.add_argument("--site",help="Provide site",dest='site',required=True)
	parser.add_argument("--vulnonly",help="Only List vulnerable Items",action="store_true")
	parser.add_argument("--coreonly",help="Only check core",action="store_true")
	parser.add_argument("--themesonly",help="Only check themes",action="store_true")
	parser.add_argument("--pluginsonly",help="Only check plugins",action="store_true")
	parser.add_argument("--nosync",help="Skip initial sync of themes/plugins directory",action="store_true")
	parser.add_argument("--debug",help="Prints extra info about what's going on",action="store_true")
	if not cmd_exists("wordshell"):
		print "Wordshell needs to be in path as executable named as wordshell"
		print "Visit http://wordshell.net to purchase"
		exit()
	x=parser.parse_args()
	wshellsite=x.site
	report=x.vulnonly
	coreonly=x.coreonly
	themesonly=x.themesonly
	pluginsonly=x.pluginsonly
	nosync=x.nosync
	debug=x.debug

	def check_core():
		# Check Core Issues
		cmd="wordshell " + wshellsite + " --list --core"
		print "Syncing & checking core"
		runProcess(cmd)

		xinp=[]
		for line in runProcess(cmd.split()):
			if line != "":
				#if line.strip() != "name,version":
				line = ' '.join(line.split()).split(" ")[3] # IndexError: list index out of range - ERROR can occur here. This is a bug in wordshell.
				xinp.append(line)
				if debug:
					print "Wordpress version: " + line

		for x in xinp:
			y=x.replace(".","").strip()
			# Hacked code here version is sent instead of plugin name and plug name is marked as blank
			x = x.replace(" ", "")
			out = ''
			if "." not in x:
				print bcolors.FAIL + "Error: Wordpress version not found.  Please check wordshell is working correctly." + bcolors.ENDC
			else:
				out=check_vuln_status(y,x,report,"wordpresses", debug)
			if out.strip() is not "":
				print out.strip()


	def check(type):

		if type == 'plugins':
			# Check Plugin Issues
			if (nosync):
				cmd="wordshell " + wshellsite + " --list --cache"
				print "Checking cached plugins"
			else:
				cmd="wordshell " + wshellsite + " --list"
				print "Syncing & checking plugins"
		elif type == 'themes':
			# Check theme issues
			if (nosync):
				cmd="wordshell " + wshellsite + " --list --theme --cache"
				print "Checking cached themes"
			else:
				cmd="wordshell " + wshellsite + " --list --theme"
				print "Syncing & checking themes"
		else:
			check_core()
			return

		runProcess(cmd)

		xinp=[]
		for line in runProcess(cmd.split()):
			if line != "":
				#print line
				#if line.strip() != "name,version":
				if "WARNING:" not in line and wshellsite in line or wshellsite == 'all':
					xinp.append(line)
					if debug:
						print line
					#with open("test.txt", "a") as myfile:
					#    zz = str(line.split())
					#    myfile.write(zz)
					#    myfile.write("\r\n")
				#print line
		for x in xinp:
			#y = x.strip(wshellsite).replace(".php", "")

			##Remove all unwanted characters including bash formatting chars
			y = x.replace(".php", "").replace("(i)", "").replace("(-)", "").replace("\x1b", "").replace("[1m", "").replace("(B[m", "")
			
			#y = y.split("    ")
			#print y.strip()
			
			##y = y.split(wshellsite,1)[1]
			#yArr = y.split(" ")
			#\y = filter(None, y)
			#y = ' '.join(y).split()
			if debug:
				print y
				print y.split()
#				print y.split()[2].decode("utf-8")

			#newlist1 = y.split()
			#print newlist1
			#newlist = [ x.replace("\x1b", "") for x in newlist1 ]
			#print newlist
			
			name2 = y.split()[2]#.replace(" ", "")
			name = name2

			##name = "".join(name2.split())
			#if "." in name:
			#	name = name.split(".")[0]
			#print "x"
			#print y
			#print y.split(" ")
			#print name2
			if debug:
				print name
			#print y.split(name2)[1].replace("(i)", "").replace("(-)", "").strip()
			#version = y.split(name2)[1].strip().split(" ")[0]

			version = y.split()[3]#.replace(" ", "")
#			print version

			# If the site name is long, the splits are different.  This should fix that
			# This should no longer be the case.  Leaving in for now but should be rechecked later
			if "." in name:
				name = y.split()[1].replace(" ", "")
				version = y.split()[2].replace(" ", "")
			#print y.split(name)
			##version = "".join(version.split())
			#y = y.strip()
			#print y.strip()
			#print y.replace(" ", "")
			if debug:
				print version
			#name = name[:]
			#version = version[4:]

			#with open("test.txt", "a") as myfile:
			#		    myfile.write(name + " " + version)
			#		    myfile.write(name + " " + "1.0")

			#print ""
			if debug:
				print name + " " + version
			#print name + " " + "1.0"
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
			out=check_vuln_status(name,version,report,type, debug)
			if out.strip() is not "":
				print out.strip()




	if coreonly:
		check('core')
	elif themesonly:
		check('themes')
	elif pluginsonly:
		check('plugins')
	else:
		check('core')
		check('themes')
		check('plugins')



if __name__ == "__main__":
   main(sys.argv[1:])