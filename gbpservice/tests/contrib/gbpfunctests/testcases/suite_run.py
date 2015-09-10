#!/usr/bin/env python
import os,sys,optparse,platform,subprocess
from commands import *

def run_func_neg():
    # Assumption is all files are in current directory
    if 'Ubuntu' in platform.linux_distribution():
        directory = "/usr/local/lib/python2.7/dist-packages/gbpfunctests/"
    else:
        directory = "/usr/lib/python2.7/site-packages/gbpfunctests/" ## in RHEL
    cmd_list=["sudo sh -c 'cat /dev/null > test_results.txt'",\
              "sudo sh -c 'cat /dev/null > func_neg.txt'",\
              "sudo sh -c 'ls *_func*.py > func_neg.txt'",\
              "sudo sh -c 'ls *_neg.py >> func_neg.txt'",\
              "sudo chmod 777 *"]
    for cmd in cmd_list:
        getoutput(cmd)
    return "func_neg.txt"

def main():
      usage = "Usage: python suite_run.py <'aci' or 'upstream'>"
      try:
         flag = sys.argv[1]
      except Exception:
         print '%s' %(usage)
         sys.exit(1)          
      fname = run_func_neg()
      num_lines = sum(1 for line in open(fname))
      print "\nNumber of Functional Test Scripts to execute = %s" %(num_lines)
      with open(fname) as f:
        for i,l in enumerate(f,1):
            print "Functional Test Script to execute now == %s" %(l)
            # Assumption: test-scripts are executable from any location
            cmd='python %s %s' %(l.strip(),flag) # Reading the line from text file, also reads trailing \n, hence we need to strip
            print cmd
            #out=getoutput(cmd)
            subprocess.call(cmd,shell=True)
      f = open("test_results.txt")
      contents = f.read()
      f.close()
      print contents
      print "\n\nTotal Number of TestCases Executed= %s" %(contents.count("TESTCASE_GBP_"))
      print "\n\nNumber of TestCases Passed= %s" %(contents.count("PASSED"))
      print "\n\nNumber of TestCases Failed= %s" %(contents.count("FAILED"))
      if contents.count("FAILED") > 0:
         sys.exit(1)
      else:
         return 0
      
if __name__ == "__main__":
    main()

