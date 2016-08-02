#!/usr/bin/python

import argparse
import sys
import os
import shutil
import subprocess
import ConfigParser
import commands
import time
import platform
from image_builder import disk_image_create as DIB

# Defines
TEMP_WORK_DIR = "tmp" 
CONFIG = ConfigParser.ConfigParser()
NEUTRON_CONF = "/etc/neutron/neutron.conf"
FILE_PATH = os.path.dirname(os.path.realpath(__file__))
CONFIGURATOR_USER_DATA = FILE_PATH + "/image_builder/configurator_user_data"
TEMPLATES_PATH = FILE_PATH + "/templates/gbp_resources.yaml"

# global values
# these src_dirs will be copied from host to inside docker image, these 
# diretories are assumed to present in src_path
src_dirs = ["gbpservice", "neutron", "neutron_lbaas", "neutron_lib"]



parser = argparse.ArgumentParser()
parser.add_argument('--build-controller-vm', action='store_true', dest='build_controller_vm',
                    default=False, help='enable building controller vm')
parser.add_argument('--image-build-cache-dir', type=str,
                    help='directory path where trusty image tar.gz can be found for building controller vm')
parser.add_argument('--enable-orchestrator', action='store_true', dest='enable_orchestrator',
                    default=False, help='enable creating orchestrator systemctl file')
parser.add_argument('--enable-proxy', action='store_true', dest='enable_proxy',
                    default=False, help='enable creating proxy systemctl file')
parser.add_argument('--create-resources', action='store_true', dest='create_resources',
                    default=False, help='enable creating nfp required resources')
parser.add_argument('--launch-controller', action='store_true', dest='launch_controller',
                    default=False, help='enable to launch controller vm')
parser.add_argument('--clean-up', action='store_true', dest='clean_up_nfp',
                    default=False, help='enable to clean up nfp services and resources')
parser.add_argument('--controller-path', type=str, dest='controller_path',
                    help='patch to the controller image')
args = parser.parse_args()

def get_src_dirs():
    print "Getting source dirs for copying inside the docker image"
    # get the operating system type
    (os_type, os_version, os_release) = platform.dist()
    if os_type == 'Ubuntu':
        src_path = "/usr/lib/python2.7/dist-packages/"
    elif os_type == 'centos':
        src_path = "/usr/lib/python2.7/site-packages/"
    else:
        print "ERROR: Unsupported Operating System(%s)" % os_type
        return 1
    for src_dir in src_dirs:
        to_copy = src_path + src_dir
        if not os.path.isdir(to_copy):
            print "ERROR: directory not found: ", to_copy
            return 1
    os.chdir(DIB.cur_dir)
    # these src_dirs will be copied from host to inside docker image
    for src_dir in src_dirs:
        to_copy = src_path + src_dir
        if(subprocess.call(["cp", "-r", to_copy, "."])):
            print "ERROR: failed to copy %s to ./ directory" % to_copy
            return 1
    return 0

def clean_src_dirs():
    os.chdir(DIB.cur_dir)
    for src_dir in src_dirs:
        subprocess.call(["rm", "-rf", src_dir])

def update_user_data():
    os.chdir(DIB.cur_dir)
    print "Updating user_data with fresh ssh key"
    subprocess.call(["bash", "edit_user_data.sh"])
    return
    

def build_configuration_vm():

    cur_dir = os.path.dirname(__file__)
    cur_dir = os.path.realpath(cur_dir)
    if not cur_dir:
        # if script is executed from current dir, get abs path
        cur_dir = os.path.realpath('./')
    # update dib current working dir
    DIB.cur_dir = cur_dir + '/image_builder'

    if(get_src_dirs()):
        return

    # update configurator user_data with a fresh rsa ssh keypair  
    update_user_data()
 
    # set the cache dir where trusty tar.gz will be present
    if args.image_build_cache_dir:
        cache_dir = args.image_build_cache_dir
    else:
        cache_dir = os.environ.get('HOME', '-1') + '/.cache/image-create'

    # create a configurattion dictionary needed by DIB
    DIB.conf['ubuntu_release']= {'release':'trusty'}
    DIB.conf['dib'] = {"image_size":10, "elements": ["configurator"], "offline": True, "cache_dir": cache_dir}

    # Build configurator VM
    ret = DIB.dib()
    if not ret:
        print "ERROR: Failed to create Configurator VM"
    else:
        print "SUCCESS, created Configurator VM: ", ret

    # clean the scr_dirs copied in PWD
    clean_src_dirs()
       
    os.chdir(cur_dir)

    return
 

def restart_nfp_orchestrator():
    try:
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["service", "nfp_orchestrator", "restart"])
    except Exception as error:
        print "Error restarting nfp_orchestrator service"
        print error
        sys.exit(1)

def restart_nfp_config_orch():
    try:
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["service", "nfp_config_orch", "restart"])
    except Exception as error:
        print "Error restarting nfp_orchestrator service"
        print error
        sys.exit(1)

def restart_nfp_proxy():
    try:
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["service", "nfp_proxy", "restart"])
    except Exception as error:
        print "Error restarting nfp_proxy service"
        print error
        sys.exit(1)

def restart_nfp_proxy_agent():
    try:
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["service", "nfp_proxy_agent", "restart"])
    except Exception as error:
        print "Error restarting nfp_proxy_agent service"
        print error
        sys.exit(1)

def create_orchestrator_ctl():
    """
    create nfp orchestrator systemctl service file
    """
    if not os.path.exists(TEMP_WORK_DIR):
        os.makedirs(TEMP_WORK_DIR)
    
    orch_ctl_file = TEMP_WORK_DIR + "/nfp_orchestrator.service"
    try:
        file = open(orch_ctl_file, 'w+')
    except:
        print "Error creating " + orch_ctl_file + " file"
        sys.exit(1)

    file.write("[Unit]\nDescription=One Convergence NFP Orchestrator\n")
    file.write("After=syslog.target network.target\n\n[Service]")
    file.write("\nUser=neutron\nExecStart=/usr/bin/nfp  --config-file ")
    file.write(" /etc/neutron/neutron.conf --config-file ")
    file.write(" /etc/neutron/plugins/ml2/ml2_conf.ini ")
    file.write(" --config-file /etc/neutron/nfp/nfp_orchestrator.ini ")
    file.write("--log-file /var/log/nfp/nfp_orchestrator.log\n\n")
    file.write("[Install]\nWantedBy=multi-user.target")
    file.close()

    if os.path.exists("/usr/lib/systemd/system"):
        shutil.copy(orch_ctl_file, "/usr/lib/systemd/system/")
    else:
        print "Error: /usr/lib/systemd/system not present"
        sys.exit(1)

    orch_config_file = TEMP_WORK_DIR + "/nfp_config_orch.service"
    try:
        file = open(orch_config_file, 'w+')
    except:
        print "Error creating " + orch_ctl_file + " file"
        sys.exit(1)

    file.write("[Unit]\nDescription=One Convergence NFP Config Orchestrator")
    file.write("\nAfter=syslog.target network.target")
    file.write("\n\n[Service]\nType=simple\nUser=neutron")
    file.write("\nExecStart=/usr/bin/nfp --config-file /etc/neutron/nfp/nfp_config_orch.ini")
    file.write(" --config-file /etc/neutron/neutron.conf --log-file /var/log/nfp/nfp_config_orch.log")
    file.write("\n\n[Install]\nWantedBy=multi-user.target")
    file.close()

    if os.path.exists("/usr/lib/systemd/system"):
        shutil.copy(orch_config_file, "/usr/lib/systemd/system/")
    else:
        print "Error: /usr/lib/systemd/system not present"
        sys.exit(1)

    try:
        shutil.rmtree(TEMP_WORK_DIR)
    except:
        print "Error: Cleaning up the temp directory"
        sys.exit(1)

def create_nfp_namespace_file():
    """
    create nfp proxy systemctl service file
    """
    if not os.path.exists(TEMP_WORK_DIR):
        os.makedirs(TEMP_WORK_DIR)
    
    proxy_tool_file = TEMP_WORK_DIR + "/nfp_namespace"
    try:
        filepx = open(proxy_tool_file, 'w+')
    except:
        print "Error creating " + proxy_tool_file + " file"
        sys.exit(1)
    filepx.write("#!/usr/bin/bash\n")
    filepx.write("\nNOVA_CONF=/etc/nova/nova.conf\nNOVA_SESSION=neutron")
    filepx.write("\n\nget_openstack_creds () {")
    filepx.write("\n\tAUTH_URI=`crudini --get $NOVA_CONF $NOVA_SESSION admin_auth_url`")
    filepx.write("\n\tADMIN_USER=`crudini --get $NOVA_CONF $NOVA_SESSION admin_username`")
    filepx.write("\n\tADMIN_PASSWD=`crudini --get $NOVA_CONF $NOVA_SESSION admin_password`")
    filepx.write("\n\tADMIN_TENANT_NAME=`crudini --get $NOVA_CONF $NOVA_SESSION admin_tenant_name`")
    filepx.write("\n\texport OS_USERNAME=$ADMIN_USER")
    filepx.write("\n\texport OS_TENANT_NAME=$ADMIN_TENANT_NAME")
    filepx.write("\n\texport OS_PASSWORD=$ADMIN_PASSWD")
    filepx.write("\n\texport OS_AUTH_URL=$AUTH_URI\n\n}")
    filepx.write("\n\nfunction namespace_delete {\n\tget_openstack_creds")
    filepx.write("\n\n\tproxyPortId=`neutron port-list | ")
    filepx.write("grep pt_nfp_proxy_pt | awk '{print $2}'`")
    filepx.write("\n\ttapName=\"tap${proxyPortId:0:11}\"\n\n\t#Deletion namespace")
    filepx.write("\n\tNFP_P=`ip netns | grep \"nfp-proxy\"`")
    filepx.write("\n\tif [ ${#NFP_P} -ne 0 ]; then\n\t\tip netns delete nfp-proxy")
    filepx.write("\n\t\techo \"namespace removed\"\n\tfi")
    filepx.write("\n\n\t#pt1 port removing from ovs")
    filepx.write("\n\tPORT=`ovs-vsctl show | grep \"$tapName\"`")
    filepx.write("\n\tif [ ${#PORT} -ne 0 ]; then")
    filepx.write("\n\t\tovs-vsctl del-port br-int $tapName")
    filepx.write("\n\t\techo \"ovs port is removed\"")
    filepx.write("\n\tfi\n\tpkill nfp_proxy")
    filepx.write("\n\n\tgbp pt-delete nfp_proxy_pt") 
    filepx.write("\n\n\techo \"nfp-proxy cleaning success.... \"\n\n}")
    filepx.write("\n\nfunction namespace_create {\n\n\tget_openstack_creds")
    filepx.write("\n\tSERVICE_MGMT_GROUP=\"svc_management_ptg\"")
    filepx.write("\n\tcidr=\"/24\"")
    filepx.write("\n\techo \"Creating new namespace nfp-proxy....\"")
    filepx.write("\n\n\t#new namespace with name proxy")
    filepx.write("\n\tNFP_P=`ip netns add nfp-proxy`")
    filepx.write("\n\tif [ ${#NFP_P} -eq 0 ]; then")
    filepx.write("\n\t\techo \"New namepace nfp-proxt create\"")
    filepx.write("\n\telse\n\t\techo \"nfp-proxy creation failed\"\n\t\texit 0")
    filepx.write("\n\tfi\n\n\t# create nfp_proxy pt")
    filepx.write("\n\tgbp pt-create --policy-target-group $SERVICE_MGMT_GROUP nfp_proxy_pt")
    filepx.write("\n\n\t# Get the nfp_proxy_pt port id, mac address")
    filepx.write("\n\tproxyPortId=`neutron port-list | grep pt_nfp_proxy_pt | awk '{print $2}'`")
    filepx.write("\n\tproxyMacAddr=`neutron port-list | grep pt_nfp_proxy_pt | awk '{print $6}'`")
    filepx.write("\n\tproxyPortIp=`neutron port-list | grep pt_nfp_proxy_pt | awk '{print $11}' | sed 's/^\"\(.*\)\"}$/\\1/'`")
    filepx.write("\n\ttapName=\"tap${proxyPortId:0:11}\"")
    filepx.write("\n\tnew_ip_cidr=\"$proxyPortIp/24\"")
    filepx.write("\n\tproxyBrd=`ipcalc -4 $proxyPortIp -m 255.255.255.0 -b | grep BROADCAST | awk -F '=' '{print $2}'`")
    filepx.write("\n\n\t# Create a tap interface and add it to the ovs bridge br-int")
    filepx.write("\n\tovs-vsctl add-port br-int $tapName -- set Interface $tapName type=internal")
    filepx.write(" external_ids:iface-id=$proxyPortId external_ids:iface-status=active external_ids:attached-mac=$proxyMacAddr")
    filepx.write("\n\n\t# Add the tap interface to proxy\n\tip link set $tapName netns nfp-proxy")
    filepx.write("\n\n\t# Get the link up\n\tip netns exec nfp-proxy ip link set $tapName up")
    filepx.write("\n\n\t# set the mac address on the tap interface\n\tip netns exec nfp-proxy ip link set $tapName address $proxyMacAddr")
    filepx.write("\n\n\t# assign ip address to the proxy tap interface")
    filepx.write("\n\tip netns exec nfp-proxy ip -4 addr add $new_ip_cidr scope global dev $tapName brd $proxyBrd")
    filepx.write("\n\n\t# Update the neutron port with the host id binding")
    filepx.write("\n\tneutron port-update $proxyPortId --binding:host_id=`hostname`")
    filepx.write("\n\n\tPING=`ip netns exec nfp-proxy ping $1 -q -c 2 > /dev/null`")
    filepx.write("\n\tif [ ${#PING} -eq 0 ]\n\tthen")
    filepx.write("\n\t\techo \"nfp-proxy namespcace creation success and reaching to $1\"")
    filepx.write("\n\telse\n\t\techo \"Fails reaching to $1\"")
    filepx.write("\n\tfi\n\n\tip netns exec nfp-proxy /usr/bin/nfp_proxy")
    filepx.write(" --config-file=/etc/neutron/nfp/nfp_proxy.ini --log-file /var/log/nfp/nfp_proxy.log")
    filepx.write("\n}")
    filepx.close()
    
    if os.path.exists("/usr/lib/python2.7/site-packages/gbpservice/nfp/tools/"):
        shutil.copy(proxy_tool_file, "/usr/lib/python2.7/site-packages/gbpservice/nfp/tools/")
        pass
    else:
        print "error: /usr/lib/python2.7/site-packages/gbpservice/nfp/tools/ not present"
        sys.exit(1)

    try:
        shutil.rmtree(TEMP_WORK_DIR)
    except:
        print "Error: Cleaning up the temp directory"
        sys.exit(1)

def create_proxy_ctl():
    """
    create nfp proxy systemctl service file
    """
    if not os.path.exists(TEMP_WORK_DIR):
        os.makedirs(TEMP_WORK_DIR)
    
    proxy_sup_file = TEMP_WORK_DIR + "/nfpproxy_startup"
    try:
        filepx = open(proxy_sup_file, 'w+')
    except:
        print "Error creating " + proxy_sup_file + " file"
        sys.exit(1)

    filepx.write("#!/usr/bin/sh\nNFP_PROXY_AGENT_INI=/etc/neutron/nfp/nfp_proxy.ini")
    filepx.write("\nCONFIGURATOR_IP=`crudini --get $NFP_PROXY_AGENT_INI NFP_CONTROLLER rest_server_address`\n")
    filepx.write(". /usr/lib/python2.7/site-packages/gbpservice/nfp/tools/nfp_namespace;")
    filepx.write("namespace_delete ;namespace_create $CONFIGURATOR_IP")
    filepx.close()
    

    proxy_ctl_file = TEMP_WORK_DIR + "/nfp_proxy.service"
    try:
        file = open(proxy_ctl_file, 'w+')
    except:
        print "Error creating " + proxy_ctl_file + " file"
        sys.exit(1)

    file.write("[Unit]\nDescription=One Convergence NFP Proxy\n")
    file.write("After=syslog.target network.target\n\n")
    file.write("\n[Service]\nUser=root\nExecStart=/usr/bin/nfpproxy_startup")
    file.write("\nRestart=on-abort")
    file.write("\n\n[Install]\nWantedBy=multi-user.target")
    file.close()

    if os.path.exists("/usr/lib/systemd/system"):
        shutil.copy(proxy_ctl_file, "/usr/lib/systemd/system/")
    else:
        print "error: /usr/lib/systemd/system not present"
        sys.exit(1)

    if os.path.exists("/usr/bin"):
        shutil.copy(proxy_sup_file, "/usr/bin/")
        os.system("chmod +x /usr/bin/nfpproxy_startup")
    else:
        print "error: /usr/bin not present"
        sys.exit(1)

    try:
        shutil.rmtree(TEMP_WORK_DIR)
    except:
        print "Error: Cleaning up the temp directory"
        sys.exit(1)

def create_proxy_agent_ctl():
    """
    create nfp proxy agent systemctl service file
    """
    if not os.path.exists(TEMP_WORK_DIR):
        os.makedirs(TEMP_WORK_DIR)
    
    proxy_ctl_file = TEMP_WORK_DIR + "/nfp_proxy_agent.service"
    try:
        file = open(proxy_ctl_file, 'w+')
    except:
        print "Error creating " + proxy_ctl_file + " file"
        sys.exit(1)

    file.write("[Unit]\nDescription=One Convergence NFP Proxy Agent")
    file.write("\nAfter=syslog.target network.target\n")
    file.write("\n[Service]\nUser=root")
    file.write("\nExecStart=/usr/bin/nfp --config-file /etc/neutron/neutron.conf ")
    file.write("--config-file /etc/neutron/nfp/nfp_proxy_agent.ini ")
    file.write("--log-file /var/log/nfp/nfp_proxy_agent.log\n")
    file.write("\n[Install]\nWantedBy=multi-user.target\n")
    file.close()

    if os.path.exists("/usr/lib/systemd/system"):
        shutil.copy(proxy_ctl_file, "/usr/lib/systemd/system/")
    else:
        print "error: /usr/lib/systemd/system not present"
        sys.exit(1)

    try:
        shutil.rmtree(TEMP_WORK_DIR)
    except:
        print "Error: Cleaning up the temp directory"
        sys.exit(1)

def get_openstack_creds():
    CONFIG.read(NEUTRON_CONF)
    AUTH_URI = CONFIG.get('keystone_authtoken', 'auth_uri')
    AUTH_USER = CONFIG.get('keystone_authtoken', 'admin_user')
    AUTH_PASSWORD = CONFIG.get('keystone_authtoken', 'admin_password')
    AUTH_TENANT_NAME = CONFIG.get('keystone_authtoken', 'admin_tenant_name')
    os.environ["OS_USERNAME" ] = AUTH_USER
    os.environ["OS_TENANT_NAME" ] = AUTH_TENANT_NAME
    os.environ["OS_PASSWORD"] = AUTH_PASSWORD
    os.environ["OS_AUTH_URL"] = AUTH_URI

def create_nfp_resources():
    """
    create nfp resources
    """
    get_openstack_creds()
    os.system("gbp l3policy-create default-nfp --ip-pool 172.16.0.0/16 --subnet-prefix-length 20 --proxy-ip-pool=172.17.0.0/16")
    l3policy_Id = commands.getstatusoutput("gbp l3policy-list | grep '\sdefault-nfp\s' | awk '{print $2}'")[1]
    os.system("gbp l2policy-create --l3-policy " + l3policy_Id + " svc_management_ptg")
    l2policy_Id = commands.getstatusoutput("gbp l2policy-list | grep '\ssvc_management_ptg\s' | awk '{print $2}'")[1]
    os.system("gbp group-create svc_management_ptg --service_management True --l2-policy " + l2policy_Id)

    # Create GBP Resources Heat stack
    os.system("heat stack-create --template-file " + TEMPLATES_PATH + " gbp_services_stack")

def launch_configurator():
    get_openstack_creds()
    if os.path.isfile(args.controller_path):
        os.system("glance image-create --name configurator --disk-format qcow2  --container-format bare  --visibility public --file " + args.controller_path )
    else:
        print "Error " + args.controller_path + " does not exist"
        sys.exit(1)
    Port_id = commands.getstatusoutput("gbp policy-target-create --policy-target-group svc_management_ptg configuratorVM_instance | grep port_id  | awk '{print $4}'")[1]
    Image_id = commands.getstatusoutput("glance image-list | grep configurator |awk '{print $2}'")[1]  
    if Image_id and Port_id:
        os.system("nova boot --flavor m1.medium --image " + Image_id + " --user-data " + CONFIGURATOR_USER_DATA + " --nic port-id=" + Port_id + " configuratorVM_instance")
    else:
        if not Port_id:
            print "Error unable to create the controller port id"
        else:
            print "Erro unable to get configurator image info"
        sys.exit(1)

def clean_up():
    """
    clean up nfp resources
    """
    get_openstack_creds()
    InstanceId = commands.getstatusoutput("nova list | grep configuratorVM_instance | awk '{print $2}'")[1]
    if InstanceId:
    	os.system("nova delete " + InstanceId)
    	time.sleep(10)

    PolicyTargetId = commands.getstatusoutput("gbp policy-target-list | grep configuratorVM_instance | awk '{print $2}'")[1]
    if PolicyTargetId:
    	os.system("gbp policy-target-delete " + PolicyTargetId)
    
    ImageId = commands.getstatusoutput("glance image-list | grep configurator | awk '{print $2}'")[1]
    if ImageId:
    	os.system("glance image-delete " + ImageId)


    ServiceMGMTId = commands.getstatusoutput("gbp group-list | grep '\ssvc_management_ptg\s' | awk '{print $2}'")[1]
    if ServiceMGMTId:
        SvcGroupId = commands.getstatusoutput("gbp group-list | grep '\ssvc_management_ptg\s' | awk '{print $2}'")[1]
        l2policyId = commands.getstatusoutput("gbp l2policy-list | grep '\ssvc_management_ptg\s' | awk '{print $2}'")[1]
        l3policyId = commands.getstatusoutput("gbp l3policy-list | grep '\sdefault-nfp\s' | awk '{print $2}'")[1]
        os.system("gbp group-delete " + SvcGroupId)
        os.system("gbp l2policy-delete " + l2policyId)
        os.system("gbp l3policy-delete " + l3policyId)

    HeatId = commands.getstatusoutput("heat stack-list | grep '\sgbp_services_stack\s' | awk '{print $2}'")[1]
    if HeatId:
    	os.system("heat stack-delete gbp_services_stack")

def main():
    if args.build_controller_vm:
        build_configuration_vm()
    elif args.enable_orchestrator:
        create_orchestrator_ctl()
        restart_nfp_orchestrator()
        restart_nfp_config_orch()
    elif args.enable_proxy:
        create_nfp_namespace_file()
        create_proxy_ctl()
        restart_nfp_proxy()
        create_proxy_agent_ctl()
        restart_nfp_proxy_agent()
    elif args.create_resources:
        create_nfp_resources()
    elif args.launch_controller:
        if args.controller_path:
            launch_configurator()
        else:
            parser.print_help()
    elif args.clean_up_nfp:
        clean_up()
    else:
        parser.print_help()
        
if __name__ == '__main__':
    main()
