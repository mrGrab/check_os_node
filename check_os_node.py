#!/usr/bin/python
#coding: UTF-8

import requests, sys, argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


parser = argparse.ArgumentParser(prog='check_os_node.py', usage='\n\t %(prog)s --ulr <openshift_master> --node <node_name> --token <bearer_token>', description='Nagios plugin to check status of openshift/kubernetes node', formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=30))
parser.add_argument('-u','--url', action='store',  help="url[:port] of openshfit master server.", required=True)
parser.add_argument('-n','--node', action='store', help="node name for which you need info", required=True)
parser.add_argument('-t','--token', action='store', help="token for connection to openshfit master", required=True)
args = parser.parse_args()

headers = {'Authorization': 'Bearer '+args.token}
params={'fieldSelector': 'spec.host='+args.node, 'status.phase': 'Running'}

try:
	req = requests.get(args.url+"/api/v1/nodes/"+args.node, verify=False, headers=headers)
	if req.status_code <> 200: raise Exception()
except BaseException:
	print "UKNOWN - can't connect to server, or wrong http response, or wrong node name"
	sys.exit(3)

for conditions in req.json()['status']['conditions']:
	if conditions['type']  == 'OutOfDisk' and conditions['status'] == 'True':
                print "ERROR OutOfDisk: True"
		sys.exit(2)
	if conditions['type']  == 'MemoryPressure' and conditions['status'] == 'True':
                print "ERROR MemoryPressure: True"
		sys.exit(2)
        if conditions['type']  == 'DiskPressure' and conditions['status'] == 'True':
                print "ERROR DiskPressure: True"
		sys.exit(2)
	if conditions['type']  == 'Ready' and conditions['status'] == 'False':
		print "ERROR Status: NotReady"
		sys.exit(2)
print "Ready: True; OutOfDisk: False; MemoryPressure: False; DiskPressure: False"
sys.exit(0)
