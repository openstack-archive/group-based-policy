#!/usr/bin/env python
import sys, time
import paramiko
import subprocess
import re
import itertools
from prettytable import PrettyTable

def sshconnect(hostname, user, passwd):
    sshclient = paramiko.SSHClient()
    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        sshclient.connect(hostname, username=user, password=passwd)
    except Exception, e:
        raise ErrorConnectingToServer("Error connecting to server %s: %s" % (hostname, e))
        sshclient = None
    return sshclient

def report_table(suite_name):
    ps = subprocess.Popen(['grep', '-r', 'TESTCASE', '/tmp/%s.log' %(suite_name)], stdout=subprocess.PIPE)
    output = ps.communicate()[0]
    #print output
    output = output.splitlines()
    line = 0
    tc_dict = {}
    while line < len(output):
        find1 = re.search('\\b(TESTCASE_GBP_.*)\\b: (.*)' , output[line], re.I)
        if find1 != None:
           line += 1
           if line <= len(output) - 1:
              find2 = re.search('\\b%s\\b: (.*)' %(find1.group(1)), output[line],re.I)
              if find2 != None:
                 tc_dict[find1.group(1)]=find2.group(1), find1.group(2)
        line += 1
    #print tc_dict
    table = PrettyTable(["TESTCASE_ID", "RESULTS", "TESTCASE_HEADER"])
    table.padding_width = 1
    for key,val in tc_dict.iteritems():
        table.add_row(["%s" %(key),"%s" %(val[0]),"%s" %(val[1])])
    return table

def report_results(suite_name,txt_file):
    orig_stdout = sys.stdout
    f = open('%s' %(txt_file),'a')
    sys.stdout = f
    report=report_table(suite_name)
    print report
    sys.stdout = orig_stdout
    f.close()

def gen_tc_header():
    comb_list = [['same_leaf','two_leafs'],['same_host','two_hosts'],['same_ptg','two_ptgs'],\
                  ['same_L3_subnet','two_L3_subnets'],['same_L2_bd','two_L2_bds']]

    out_hdr_list=list(itertools.product(*comb_list))
    out_headers = []
    for hdr in out_hdr_list:
        header = 'test_'+'_'.join(str(i) for i in hdr)
        out_headers.append(header)
    #proto = map(list,list(itertools.combinations(['icmp','tcp','udp','dhcp','arp'],2)))
    proto = list(itertools.combinations(['icmp','tcp','udp','dhcp','arp'],2))
    proto_hdrs = []
    for hdr in proto:
        proto_header = '_'.join(str(i) for i in hdr)
        proto_hdrs.append(proto_header)
    in_hdrs = list(itertools.product(out_headers,proto_hdrs))
    final_headers = []
    for hdr in in_hdrs:
        tc_header = '_'.join(str(i) for i in hdr)
        final_headers.append(tc_header)
    table = PrettyTable(["TESTCASE_ID", "STATUS", "TESTCASE_HEADER"])
    table.padding_width = 1
    for i in range(len(final_headers)):
        table.add_row(["TESTCASE_DP_%s" %(i+1),"TBA","%s" %(final_headers[i])])
    print table
#tc_gen= gen_tc_header()
