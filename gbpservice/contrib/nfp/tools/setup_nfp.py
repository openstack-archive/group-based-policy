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
NEUTRON_ML2_CONF = "/etc/neutron/plugins/ml2/ml2_conf.ini"
FILE_PATH = os.path.dirname(os.path.realpath(__file__))
CONFIGURATOR_USER_DATA = FILE_PATH + "/image_builder/configurator_user_data"
TEMPLATES_PATH = FILE_PATH + "/templates/gbp_resources.yaml"
APIC_ENV = False

# global values
# these src_dirs will be copied from host to inside docker image, these
# diretories are assumed to present in src_path
src_dirs = ["gbpservice", "neutron", "neutron_lbaas", "neutron_lib"]
# create a temp directory for copying srcs
dst_dir = "/tmp/controller_docker_build/"


parser = argparse.ArgumentParser()
parser.add_argument('--configure', action='store_true',
                    dest='configure_nfp',
                    default=False, help='Configure NFP')
parser.add_argument('--build-controller-vm', action='store_true',
                    dest='build_controller_vm',
                    default=False, help='enable building controller vm')
parser.add_argument('--image-build-cache-dir', type=str,
                    help=('directory path where trusty image tar.gz'
                          ' can be found for building controller vm'))
parser.add_argument('--enable-orchestrator', action='store_true',
                    dest='enable_orchestrator',
                    default=False,
                    help='enable creating orchestrator systemctl file')
parser.add_argument('--enable-proxy', action='store_true',
                    dest='enable_proxy',
                    default=False,
                    help='enable creating proxy systemctl file')
parser.add_argument('--create-resources', action='store_true',
                    dest='create_resources',
                    default=False,
                    help='enable creating nfp required resources')
parser.add_argument('--launch-controller', action='store_true',
                    dest='launch_controller',
                    default=False, help='enable to launch controller vm')
parser.add_argument('--configure-ext-net',
                    action='store_true', default=False,
                    help=('Configure heat driver section in nfp.ini.'
                          ' Specify external network name with --ext-net-name option.'))
parser.add_argument('--ext-net-name', type=str,
                    default='',
                    help=('Provide external network(neutron network) name.'
                          ' Use along with --configure-ext-net.'))
parser.add_argument('--clean-up', action='store_true', dest='clean_up_nfp',
                    default=False,
                    help='enable to clean up nfp services and resources')
parser.add_argument('--controller-path', type=str, dest='controller_path',
                    help='patch to the controller image')
args = parser.parse_args()

def check_if_apic_sys():
    global APIC_ENV
    mech_drivers = commands.getoutput("crudini --get " + NEUTRON_ML2_CONF + " ml2 mechanism_drivers")
    if mech_drivers == 'apic_gbp':
        APIC_ENV = True

def set_keystone_authtoken_section():
    global NEUTRON_CONF
    nfp_conf = '/etc/nfp.ini'
    admin_user = commands.getoutput("crudini --get " + NEUTRON_CONF + " keystone_authtoken username")
    admin_password = commands.getoutput("crudini --get " + NEUTRON_CONF + " keystone_authtoken password")
    admin_tenant_name = commands.getoutput("crudini --get " + NEUTRON_CONF + " keystone_authtoken project_name")
    auth_uri = commands.getoutput("crudini --get " + NEUTRON_CONF + " keystone_authtoken auth_uri")
    auth_protocol = commands.getoutput("echo " + auth_uri + " | cut -d':' -f1")
    auth_host = commands.getoutput("echo " + auth_uri + " | cut -d'/' -f3 | cut -d':' -f1")
    auth_port = commands.getoutput("echo " + auth_uri + " | cut -d'/' -f3 | cut -d':' -f2")
    auth_version = commands.getoutput("echo " + auth_uri + " | cut -d'/' -f4")
    if auth_version == '':
        auth_version = 'v2.0'
    subprocess.call(("crudini --set " + nfp_conf + " nfp_keystone_authtoken admin_user " + admin_user).split(' '))
    subprocess.call(("crudini --set " + nfp_conf + " nfp_keystone_authtoken admin_password " + admin_password).split(' '))
    subprocess.call(("crudini --set " + nfp_conf + " nfp_keystone_authtoken admin_tenant_name " + admin_tenant_name).split(' '))
    subprocess.call(("crudini --set " + nfp_conf + " nfp_keystone_authtoken auth_protocol " + auth_protocol).split(' '))
    subprocess.call(("crudini --set " + nfp_conf + " nfp_keystone_authtoken auth_host " + auth_host).split(' '))
    subprocess.call(("crudini --set " + nfp_conf + " nfp_keystone_authtoken auth_port " + auth_port).split(' '))
    subprocess.call(("crudini --set " + nfp_conf + " nfp_keystone_authtoken auth_version " + auth_version).split(' '))

def configure_nfp():
    commands.getoutput("cat /usr/lib/python2.7/site-packages/gbpservice/contrib/nfp/bin/nfp.ini >> /etc/nfp.ini")
    commands.getoutput("mkdir -p /etc/nfp/vyos/")
    commands.getoutput("cp -r /usr/lib/python2.7/site-packages/gbpservice/contrib/nfp/bin/vyos.day0 /etc/nfp/vyos/")
    commands.getoutput("sed -i 's/\"password\": \"\"/\"password\": \"vyos\"/' /etc/nfp/vyos/vyos.day0")
    set_keystone_authtoken_section()
    check_if_apic_sys()
    curr_service_plugins = commands.getoutput("crudini --get /etc/neutron/neutron.conf DEFAULT service_plugins")
    curr_service_plugins_list = curr_service_plugins.split(",")
    lbaas_enabled = filter(lambda x: 'lbaas' in x, curr_service_plugins_list)
    vpnaas_enabled = filter(lambda x: 'vpnaas' in x, curr_service_plugins_list)
    fwaas_enabled = filter(lambda x: 'fwaas' in x, curr_service_plugins_list)
    firewall_enabled = filter(lambda x: 'firewall' in x, curr_service_plugins_list)
    for word in firewall_enabled:
       if word not in fwaas_enabled:
           fwaas_enabled.append(word)
    plugins_to_enable = ["ncp"]
    for plugin in plugins_to_enable:
        if plugin not in curr_service_plugins_list:
            curr_service_plugins_list.append(plugin)

    if "servicechain" in curr_service_plugins_list:
         curr_service_plugins_list.remove("servicechain")

    if not len(vpnaas_enabled):
        curr_service_plugins_list.append("vpnaas")
    else:
        for word in vpnaas_enabled:
            curr_service_plugins_list.remove(word)
        curr_service_plugins_list.append("vpnaas")

    # enable lbaasv2 by default
    if not len(lbaas_enabled):
        curr_service_plugins_list.append("lbaasv2")
    else:
        for word in lbaas_enabled:
            curr_service_plugins_list.remove(word)
        curr_service_plugins_list.append("lbaasv2")

    if not len(fwaas_enabled):
        curr_service_plugins_list.append("nfp_fwaas")
    else:
        for word in fwaas_enabled:
            curr_service_plugins_list.remove(word)
        curr_service_plugins_list.append("nfp_fwaas")

    new_service_plugins_list = curr_service_plugins_list
    new_service_plugins = ",".join(new_service_plugins_list)
    subprocess.call(("crudini --set /etc/neutron/neutron.conf DEFAULT service_plugins " + str(new_service_plugins)).split(' '))

    #check id gbp-heat is configured, if not configure
    curr_heat_plugin_dirs = commands.getoutput("crudini --get /etc/heat/heat.conf DEFAULT plugin_dirs")
    curr_heat_plugin_dirs_list =  curr_heat_plugin_dirs.split(",")
    heat_dirs_to_enable = ["/usr/lib64/heat", "/usr/lib/heat", "/usr/lib/python2.7/site-packages/gbpautomation/heat"]
    for dir in heat_dirs_to_enable:
        if dir not in curr_heat_plugin_dirs_list:
            curr_heat_plugin_dirs_list.append(dir)
    new_heat_plugin_dirs_list = curr_heat_plugin_dirs_list
    new_heat_plugin_dirs = ",".join(new_heat_plugin_dirs_list)
    subprocess.call(("crudini --set /etc/heat/heat.conf DEFAULT plugin_dirs " + str(new_heat_plugin_dirs)).split(' '))

    # Enable GBP extension driver for service sharing
    if not APIC_ENV:
        subprocess.call("crudini --set /etc/neutron/neutron.conf group_policy policy_drivers implicit_policy,resource_mapping,chain_mapping".split(' '))
    else:
        subprocess.call("crudini --set /etc/neutron/neutron.conf group_policy policy_drivers implicit_policy,apic,chain_mapping".split(' '))
        # Configure policy_drivers if section group_policy exists in the config file
        ret = subprocess.call("crudini --get /etc/neutron/plugins/ml2/ml2_conf_cisco_apic.ini group_policy".split(' '))
        if not ret:
            subprocess.call("crudini --set /etc/neutron/plugins/ml2/ml2_conf_cisco_apic.ini group_policy policy_drivers implicit_policy,apic,chain_mapping".split(' '))

    subprocess.call("crudini --set /etc/neutron/neutron.conf group_policy extension_drivers proxy_group".split(' '))

    # Configure service owner
    subprocess.call("crudini --set /etc/neutron/neutron.conf admin_owned_resources_apic_tscp plumbing_resource_owner_user neutron".split(' '))
    admin_password = commands.getoutput("crudini --get /etc/neutron/neutron.conf keystone_authtoken password")
    subprocess.call("crudini --set /etc/neutron/neutron.conf admin_owned_resources_apic_tscp plumbing_resource_owner_password".split(' ') + [admin_password])
    subprocess.call("crudini --set /etc/neutron/neutron.conf admin_owned_resources_apic_tscp plumbing_resource_owner_tenant_name services".split(' '))

    # Configure NFP drivers
    subprocess.call("crudini --set /etc/neutron/neutron.conf node_composition_plugin node_plumber admin_owned_resources_apic_plumber".split(' '))
    subprocess.call("crudini --set /etc/neutron/neutron.conf node_composition_plugin node_drivers nfp_node_driver".split(' '))
    subprocess.call("crudini --set /etc/neutron/neutron.conf nfp_node_driver is_service_admin_owned False".split(' '))
    subprocess.call("crudini --set /etc/neutron/neutron.conf nfp_node_driver svc_management_ptg_name svc_management_ptg".split(' '))

    # Enable ML2 port security
    subprocess.call("crudini --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 extension_drivers port_security".split(' '))

    # Update neutron server to use GBP policy
    subprocess.call("crudini --set /etc/neutron/neutron.conf DEFAULT policy_file /etc/group-based-policy/policy.d/policy.json".split(' '))

    # Update neutron LBaaS with NFP LBaaS v2 service provider
    subprocess.call("crudini --set /etc/neutron/neutron_lbaas.conf service_providers service_provider LOADBALANCERV2:loadbalancerv2:gbpservice.contrib.nfp.service_plugins.loadbalancer.drivers.nfp_lbaasv2_plugin_driver.HaproxyOnVMPluginDriver:default".split(' '))

    # Update neutron VPNaaS with NFP VPNaaS service provider
    subprocess.call(["grep -q '^service_provider.*NFPIPsecVPNDriver:default' /etc/neutron/neutron_vpnaas.conf; if [[ $? = 1 ]]; then sed -i '/^service_provider.*IPsecVPNDriver/ s/:default/\\nservice_provider\ =\ VPN:vpn:gbpservice.contrib.nfp.service_plugins.vpn.drivers.nfp_vpnaas_driver.NFPIPsecVPNDriver:default/' /etc/neutron/neutron_vpnaas.conf; fi"], shell=True)

    # Update DB
    subprocess.call("gbp-db-manage --config-file /usr/share/neutron/neutron-dist.conf --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugin.ini upgrade head".split(' '))

    # Restart the services to make the configuration effective
    subprocess.call("systemctl restart nfp_orchestrator".split(' '))
    subprocess.call("systemctl restart nfp_config_orch".split(' '))
    subprocess.call("systemctl restart openstack-heat-engine".split(' '))
    subprocess.call("systemctl restart neutron-server".split(' '))


def get_src_dirs():
    print("Getting source dirs for copying inside the docker image")
    # get the operating system type
    (os_type, os_version, os_release) = platform.dist()
    if os_type in ['Ubuntu']:
        src_path = "/usr/lib/python2.7/dist-packages/"
    elif os_type in ['centos', 'redhat']:
        src_path = "/usr/lib/python2.7/site-packages/"
    else:
        print("ERROR: Unsupported Operating System(%s)" % os_type)
        return 1
    for src_dir in src_dirs:
        to_copy = src_path + src_dir
        if not os.path.isdir(to_copy):
            print("ERROR: directory not found: ", to_copy)
            return 1
    # create a tmp directory for creating configurator docker
    subprocess.call(["rm", "-rf", dst_dir])
    os.mkdir(dst_dir)
    dockerfile = DIB.cur_dir + "/Dockerfile"
    run_sh = DIB.cur_dir + "/configurator_run.sh"
    # these src_dirs will be copied from host to inside docker image
    for src_dir in src_dirs:
        to_copy = src_path + src_dir
        if(subprocess.call(["cp", "-r", to_copy, dst_dir])):
            print("ERROR: failed to copy %s to ./ directory" % to_copy)
            return 1
    subprocess.call(["cp", dockerfile, dst_dir])
    subprocess.call(["cp", run_sh, dst_dir])
    DIB.docker_build_dir = dst_dir

    return 0


def clean_src_dirs():
    subprocess.call(["rm", "-rf", dst_dir])


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

    # set the cache dir where trusty tar.gz will be present
    if args.image_build_cache_dir:
        cache_dir = args.image_build_cache_dir
    else:
        cache_dir = os.environ.get('HOME', '-1') + '/.cache/image-create'

    # create a configurattion dictionary needed by DIB
    DIB.conf['ubuntu_release'] = {'release': 'trusty'}
    DIB.conf['dib'] = {"image_size": 10, "elements": ["configurator", "root-passwd"],
                       "root_pswd": "nfp123",
                       "offline": True, "cache_dir": cache_dir}

    # Build configurator VM
    (ret, image) = DIB.dib()
    if not ret:
        print("ERROR: Failed to create Configurator VM")
    else:
        print("SUCCESS, created Configurator VM: ", image)

    # clean the scr_dirs copied in PWD
    clean_src_dirs()

    os.chdir(cur_dir)

    return


def restart_nfp_orchestrator():
    try:
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["service", "nfp_orchestrator", "restart"])
    except Exception as error:
        print("Error restarting nfp_orchestrator service")
        print(error)
        sys.exit(1)


def restart_nfp_config_orch():
    try:
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["service", "nfp_config_orch", "restart"])
    except Exception as error:
        print("Error restarting nfp_orchestrator service")
        print(error)
        sys.exit(1)


def restart_nfp_proxy():
    try:
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["service", "nfp_proxy", "restart"])
    except Exception as error:
        print("Error restarting nfp_proxy service")
        print(error)
        sys.exit(1)


def restart_nfp_proxy_agent():
    try:
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["service", "nfp_proxy_agent", "restart"])
    except Exception as error:
        print("Error restarting nfp_proxy_agent service")
        print(error)
        sys.exit(1)


def create_orchestrator_ctl():
    """
    create nfp orchestrator systemctl service file
    """

    if not os.path.exists("/var/log/nfp"):
        os.makedirs("/var/log/nfp")
        os.system("chown neutron:neutron /var/log/nfp")

    if not os.path.exists(TEMP_WORK_DIR):
        os.makedirs(TEMP_WORK_DIR)

    orch_ctl_file = TEMP_WORK_DIR + "/nfp_orchestrator.service"
    try:
        file = open(orch_ctl_file, 'w+')
    except:
        print("Error creating " + orch_ctl_file + " file")
        sys.exit(1)

    file.write("[Unit]\nDescription=One Convergence NFP Orchestrator\n")
    file.write("After=syslog.target network.target\n\n[Service]")
    file.write("\nUser=neutron\nExecStart=/usr/bin/nfp  --module orchestrator")
    file.write(" --config-file /etc/neutron/neutron.conf --config-file ")
    file.write(" /etc/neutron/plugins/ml2/ml2_conf.ini ")
    file.write(" --config-file /etc/nfp.ini ")
    file.write("--log-file /var/log/nfp/nfp_orchestrator.log\n\n")
    file.write("[Install]\nWantedBy=multi-user.target")
    file.close()

    if os.path.exists("/usr/lib/systemd/system"):
        shutil.copy(orch_ctl_file, "/usr/lib/systemd/system/")
    else:
        print("Error: /usr/lib/systemd/system not present")
        sys.exit(1)

    subprocess.call(["systemctl", "enable", "nfp_orchestrator"])

    orch_config_file = TEMP_WORK_DIR + "/nfp_config_orch.service"
    try:
        file = open(orch_config_file, 'w+')
    except:
        print("Error creating " + orch_ctl_file + " file")
        sys.exit(1)

    file.write("[Unit]\nDescription=One Convergence NFP Config Orchestrator")
    file.write("\nAfter=syslog.target network.target")
    file.write("\n\n[Service]\nType=simple\nUser=neutron")
    file.write("\nExecStart=/usr/bin/nfp"
               " --module config_orchestrator"
               " --config-file /etc/nfp.ini")
    file.write(" --config-file /etc/neutron/neutron.conf"
               " --log-file /var/log/nfp/nfp_config_orch.log")
    file.write("\n\n[Install]\nWantedBy=multi-user.target")
    file.close()

    if os.path.exists("/usr/lib/systemd/system"):
        shutil.copy(orch_config_file, "/usr/lib/systemd/system/")
    else:
        print("Error: /usr/lib/systemd/system not present")
        sys.exit(1)

    subprocess.call(["systemctl", "enable", "nfp_config_orch"])

    try:
        shutil.rmtree(TEMP_WORK_DIR)
    except:
        print("Error: Cleaning up the temp directory")
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
        print("Error creating " + proxy_tool_file + " file")
        sys.exit(1)
    filepx.write("#!/usr/bin/bash\n")
    filepx.write("\nNOVA_CONF=/etc/nova/nova.conf\nNOVA_SESSION=neutron")
    filepx.write("\n\nget_openstack_creds () {")
    filepx.write("\n\tAUTH_URI=`crudini --get $NOVA_CONF $NOVA_SESSION auth_url`")
    filepx.write("\n\t# if auth_url option is not available, look for admin_auth_url"
                 "\n\tif [[ $? = 1 ]]; then"
                 "\n\t\tAUTH_URI=`crudini --get $NOVA_CONF $NOVA_SESSION admin_auth_url`"
                 "\n\tfi")
    filepx.write("\n\tADMIN_USER=`crudini --get $NOVA_CONF $NOVA_SESSION username`")
    filepx.write("\n\t# if username option is not available, look for admin_username"
                 "\n\tif [[ $? = 1 ]]; then"
                 "\n\t\tADMIN_USER=`crudini --get $NOVA_CONF $NOVA_SESSION admin_username`")
    filepx.write("\n\t\t# if admin_username option is not available, look for admin_user"
                 "\n\t\tif [[ $? = 1 ]]; then"
                 "\n\t\t\tADMIN_USER=`crudini --get $NOVA_CONF $NOVA_SESSION admin_user`"
                 "\n\t\tfi"
                 "\n\tfi")
    filepx.write("\n\tADMIN_PASSWD=`crudini --get $NOVA_CONF $NOVA_SESSION password`")
    filepx.write("\n\t# if password option is not available, look for admin_password"
                 "\n\tif [[ $? = 1 ]]; then"
                 "\n\t\tADMIN_PASSWD=`crudini --get $NOVA_CONF $NOVA_SESSION admin_password`"
                 "\n\tfi")
    filepx.write("\n\tADMIN_TENANT_NAME=`crudini --get $NOVA_CONF $NOVA_SESSION project_name`")
    filepx.write("\n\t# if project_name option is not available, look for admin_tenant_name"
                 "\n\tif [[ $? = 1 ]]; then"
                 "\n\t\tADMIN_TENANT_NAME=`crudini --get $NOVA_CONF $NOVA_SESSION admin_tenant_name`"
                 "\n\tfi")
    filepx.write("\n\texport OS_USERNAME=$ADMIN_USER")
    filepx.write("\n\texport OS_TENANT_NAME=$ADMIN_TENANT_NAME")
    filepx.write("\n\texport OS_PASSWORD=$ADMIN_PASSWD")
    filepx.write("\n\tif [[ $AUTH_URI == *\"v3\"* ]]; then"
                 "\n\t\tADMIN_PROJECT_DOMAIN_NAME=`crudini --get $NOVA_CONF"
                 " $NOVA_SESSION project_domain_name`"
                 "\n\t\tADMIN_USER_DOMAIN_NAME=`crudini --get $NOVA_CONF"
                 " $NOVA_SESSION user_domain_name`"
                 "\n\t\texport OS_PROJECT_DOMAIN_NAME=$ADMIN_PROJECT_DOMAIN_NAME"
                 "\n\t\texport OS_USER_DOMAIN_NAME=$ADMIN_USER_DOMAIN_NAME"
                 "\n\tfi")
    filepx.write("\n\texport OS_AUTH_URL=$AUTH_URI\n\n}")
    filepx.write("\n\nfunction namespace_delete {\n\tget_openstack_creds")
    filepx.write("\n\n\tproxyPortId=`neutron port-list | ")
    filepx.write("grep pt_nfp_proxy_pt | awk '{print $2}'`")
    filepx.write("\n\ttapName=\"tap${proxyPortId:0:11}\"\n\n"
                 "\t#Deletion namespace")
    filepx.write("\n\tNFP_P=`ip netns | grep \"nfp-proxy\"`")
    filepx.write("\n\tif [ ${#NFP_P} -ne 0 ]; then\n\t\t"
                 "ip netns delete nfp-proxy")
    filepx.write("\n\t\techo \"namespace removed\"\n\tfi")
    filepx.write("\n\n\t#pt1 port removing from ovs")
    filepx.write("\n\tPORT=`ovs-vsctl show | grep \"$tapName\"`")
    filepx.write("\n\tif [ ${#PORT} -ne 0 ]; then")
    filepx.write("\n\t\tovs-vsctl del-port br-int $tapName")
    filepx.write("\n\t\techo \"ovs port is removed\"")
    filepx.write("\n\tfi\n\tpkill nfp_proxy")
    filepx.write("\n\n\tgbp pt-delete nfp_proxy_pt")
    filepx.write("\n\n\techo \"nfp-proxy cleaning success.... \"\n\n}")
    filepx.write("\n\nfunction netmask_to_bitmask {")
    filepx.write("\n\tnetmask_bits=$1")
    filepx.write("\n\tset -- $(( 5 - ($netmask_bits / 8) )) 255 255 255 255 $(( (255 << (8 - ($netmask_bits % 8))) & 255 )) 0 0 0")
    filepx.write("\n\t[ $1 -gt 1 ] && shift $1 || shift")
    filepx.write("\n\tnetmask=${1-0}.${2-0}.${3-0}.${4-0}\n}")
    filepx.write("\n\nfunction namespace_create {\n\n\tget_openstack_creds")
    filepx.write("\n\tSERVICE_MGMT_GROUP=\"svc_management_ptg\"")
    filepx.write("\n\tnetmask_bits=`neutron net-list --name l2p_$SERVICE_MGMT_GROUP -F subnets  -f value | awk '{print $2}' | awk -F'/' '{print $2}'`")
    filepx.write("\n\techo \"Creating new namespace nfp-proxy....\"")
    filepx.write("\n\n\t#new namespace with name proxy")
    filepx.write("\n\tNFP_P=`ip netns add nfp-proxy`")
    filepx.write("\n\tif [ ${#NFP_P} -eq 0 ]; then")
    filepx.write("\n\t\techo \"New namepace nfp-proxy create\"")
    filepx.write("\n\telse\n\t\techo \"nfp-proxy creation failed\"\n\t\t"
                 "exit 0")
    filepx.write("\n\tfi\n\n\t# create nfp_proxy pt")
    filepx.write("\n\tgbp pt-create --policy-target-group $SERVICE_MGMT_GROUP"
                 " nfp_proxy_pt")
    filepx.write("\n\n\t# Get the nfp_proxy_pt port id, mac address")
    filepx.write("\n\tproxyPortId=`neutron port-list | grep pt_nfp_proxy_pt"
                 " | awk '{print $2}'`")
    filepx.write("\n\tproxyMacAddr=`neutron port-list | grep pt_nfp_proxy_pt"
                 " | awk '{print $6}'`")
    filepx.write("\n\tproxyPortIp=`neutron port-list | grep pt_nfp_proxy_pt"
                 " | awk '{print $11}' | sed 's/^\"\(.*\)\"}$/\\1/'`")
    filepx.write("\n\ttapName=\"tap${proxyPortId:0:11}\"")
    filepx.write("\n\tnew_ip_cidr=\"$proxyPortIp/$netmask_bits\"")
    filepx.write("\n\tnetmask_to_bitmask $netmask_bits\n")
    filepx.write("\n\tproxyBrd=`ipcalc -4 $proxyPortIp -m $netmask -b"
                 " | grep BROADCAST | awk -F '=' '{print $2}'`")
    filepx.write("\n\n\t# Create a tap interface and add it"
                 " to the ovs bridge br-int")
    filepx.write("\n\tovs-vsctl add-port br-int $tapName -- set Interface"
                 " $tapName type=internal")
    filepx.write(" external_ids:iface-id=$proxyPortId"
                 " external_ids:iface-status=active"
                 " external_ids:attached-mac=$proxyMacAddr")
    filepx.write("\n\n\t# Add the tap interface to proxy\n\t"
                 "ip link set $tapName netns nfp-proxy")
    filepx.write("\n\n\t# Get the link up\n\tip netns exec nfp-proxy"
                 " ip link set $tapName up")
    filepx.write("\n\n\t# set the mac address on the tap interface\n\t"
                 "ip netns exec nfp-proxy"
                 " ip link set $tapName address $proxyMacAddr")
    filepx.write("\n\n\t# assign ip address to the proxy tap interface")
    filepx.write("\n\tip netns exec nfp-proxy ip -4 addr add"
                 " $new_ip_cidr scope global dev $tapName brd $proxyBrd")
    filepx.write("\n\n\t# Update the neutron port with the host id binding")
    filepx.write("\n\tneutron port-update $proxyPortId"
                 " --binding:host_id=`hostname`")
    filepx.write("\n\n\tPING=`ip netns exec nfp-proxy"
                 " ping $1 -q -c 2 > /dev/null`")
    filepx.write("\n\tif [ ${#PING} -eq 0 ]\n\tthen")
    filepx.write("\n\t\techo \"nfp-proxy namespcace creation success and"
                 " reaching to $1\"")
    filepx.write("\n\telse\n\t\techo \"Fails reaching to $1\"")
    filepx.write("\n\tfi\n\n\tip netns exec nfp-proxy /usr/bin/nfp_proxy")
    filepx.write(" --config-file=$2"
                 " --log-file /var/log/nfp/nfp_proxy.log")
    filepx.write("\n}")
    filepx.close()

    if os.path.exists("/usr/lib/python2.7/site-packages/gbpservice/nfp/"
                      "tools/"):
        shutil.copy(proxy_tool_file,
                    "/usr/lib/python2.7/site-packages/gbpservice/nfp/tools/")
    else:
        os.makedirs("/usr/lib/python2.7/site-packages/gbpservice/nfp/tools")
        shutil.copy(proxy_tool_file, "/usr/lib/python2.7/site-packages/gbpservice/nfp/tools/")

    try:
        shutil.rmtree(TEMP_WORK_DIR)
    except:
        print("Error: Cleaning up the temp directory")
        sys.exit(1)


def create_proxy_ctl():
    """
    create nfp proxy systemctl service file
    """

    if not os.path.exists("/var/log/nfp"):
        os.makedirs("/var/log/nfp")

    if not os.path.exists(TEMP_WORK_DIR):
        os.makedirs(TEMP_WORK_DIR)

    proxy_sup_file = TEMP_WORK_DIR + "/nfpproxy_startup"
    try:
        filepx = open(proxy_sup_file, 'w+')
    except:
        print("Error creating " + proxy_sup_file + " file")
        sys.exit(1)

    filepx.write("#!/usr/bin/sh\nNFP_PROXY_AGENT_INI=/etc/nfp.ini")
    filepx.write("\nCONFIGURATOR_IP=`crudini --get $NFP_PROXY_AGENT_INI"
                 " PROXY nfp_controller_ip`\n")
    filepx.write(". /usr/lib/python2.7/site-packages/gbpservice/nfp/tools/"
                 "nfp_namespace;")
    filepx.write("namespace_delete ;namespace_create $CONFIGURATOR_IP $NFP_PROXY_AGENT_INI")
    filepx.close()

    proxy_ctl_file = TEMP_WORK_DIR + "/nfp_proxy.service"
    try:
        file = open(proxy_ctl_file, 'w+')
    except:
        print("Error creating " + proxy_ctl_file + " file")
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
        print("error: /usr/lib/systemd/system not present")
        sys.exit(1)

    if os.path.exists("/usr/bin"):
        shutil.copy(proxy_sup_file, "/usr/bin/")
        os.system("chmod +x /usr/bin/nfpproxy_startup")
    else:
        print("error: /usr/bin not present")
        sys.exit(1)

    subprocess.call(["systemctl", "enable", "nfp_proxy"])

    try:
        shutil.rmtree(TEMP_WORK_DIR)
    except:
        print("Error: Cleaning up the temp directory")
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
        print("Error creating " + proxy_ctl_file + " file")
        sys.exit(1)

    file.write("[Unit]\nDescription=One Convergence NFP Proxy Agent")
    file.write("\nAfter=syslog.target network.target\n")
    file.write("\n[Service]\nUser=root")
    file.write("\nExecStart=/usr/bin/nfp --module proxy_agent "
               "--config-file /etc/neutron/neutron.conf ")
    file.write("--config-file /etc/nfp.ini ")
    file.write("--log-file /var/log/nfp/nfp_proxy_agent.log\n")
    file.write("\n[Install]\nWantedBy=multi-user.target\n")
    file.close()

    if os.path.exists("/usr/lib/systemd/system"):
        shutil.copy(proxy_ctl_file, "/usr/lib/systemd/system/")
    else:
        print("error: /usr/lib/systemd/system not present")
        sys.exit(1)

    subprocess.call(["systemctl", "enable", "nfp_proxy_agent"])

    try:
        shutil.rmtree(TEMP_WORK_DIR)
    except:
        print("Error: Cleaning up the temp directory")
        sys.exit(1)


def get_openstack_creds():
    CONFIG.read(NEUTRON_CONF)
    AUTH_URI = CONFIG.get('keystone_authtoken', 'auth_uri')
    AUTH_USER = CONFIG.get('keystone_authtoken', 'username')
    AUTH_PASSWORD = CONFIG.get('keystone_authtoken', 'password')
    AUTH_TENANT_NAME = CONFIG.get('keystone_authtoken', 'project_name')
    os.environ["OS_USERNAME"] = AUTH_USER
    os.environ["OS_TENANT_NAME"] = AUTH_TENANT_NAME
    os.environ["OS_PASSWORD"] = AUTH_PASSWORD
    os.environ["OS_AUTH_URL"] = AUTH_URI


def create_nfp_resources():
    """
    create nfp resources
    """
    get_openstack_creds()
    os.system("gbp l3policy-create default-nfp --ip-pool 172.16.0.0/16"
              " --subnet-prefix-length 20 --proxy-ip-pool=172.17.0.0/16")
    l3policy_Id = commands.getstatusoutput(
        "gbp l3policy-list | grep '\sdefault-nfp\s' | awk '{print $2}'")[1]
    os.system("gbp l2policy-create --l3-policy " +
              l3policy_Id + " svc_management_ptg")
    l2policy_Id = commands.getstatusoutput(
        "gbp l2policy-list | grep '\ssvc_management_ptg\s'"
        " | awk '{print $2}'")[1]
    os.system("gbp group-create svc_management_ptg --service_management True"
              " --l2-policy " + l2policy_Id)

    # Create GBP Resources Heat stack
    os.system("heat stack-create --poll --template-file " + TEMPLATES_PATH +
              " gbp_services_stack")


def add_nova_key_pair():
    tools_dir = os.path.dirname(__file__)
    tools_dir = os.path.realpath(tools_dir)
    if not tools_dir:
        # if script is executed from current dir, get abs path
        tools_dir = os.path.realpath('./')
    os.chdir(tools_dir)
    subprocess.call(["mkdir", "-p", "keys"])

    configurator_key_name = "configurator_key"
    print("Creating nova keypair for configurator VM.")
    pem_file_content = commands.getoutput("nova keypair-add" + " " + configurator_key_name)
    with open("keys/configurator_key.pem", "w") as f:
        f.write(pem_file_content)
    os.chmod("keys/configurator_key.pem", 0o600)
    return configurator_key_name


def launch_configurator():
    get_openstack_creds()
    if os.path.isfile(args.controller_path):
        os.system("glance image-create --name nfp_controller"
                  " --disk-format qcow2  --container-format bare"
                  "  --visibility public --file " + args.controller_path)
    else:
        print("Error " + args.controller_path + " does not exist")
        sys.exit(1)

    # add nova keypair for nfp_controller VM.
    configurator_key_name = add_nova_key_pair()

    Port_id = commands.getstatusoutput(
        "gbp policy-target-create --policy-target-group svc_management_ptg"
        " nfp_controllerVM_instance | grep port_id  | awk '{print $4}'")[1]
    Image_id = commands.getstatusoutput(
        "glance image-list | grep nfp_controller |awk '{print $2}'")[1]
    if Image_id and Port_id:
        os.system("nova boot --flavor m1.medium --image " +
                  Image_id + " --user-data " + CONFIGURATOR_USER_DATA +
                  " --key-name " + configurator_key_name +
                  " --nic port-id=" + Port_id + " nfp_controllerVM_instance")
    else:
        if not Port_id:
            print("Error unable to create the controller port id")
        else:
            print("Error unable to get nfp_controller image info")
        sys.exit(1)


def configure_ext_net(ext_net_name):
    os.system("crudini --set /etc/nfp.ini heat_driver"
              " internet_out_network_name %s"
              % (ext_net_name))
    subprocess.call("systemctl restart nfp_orchestrator".split(' '))


def clean_up():
    """
    clean up nfp resources
    """
    get_openstack_creds()
    InstanceId = commands.getstatusoutput(
        "nova list | grep nfp_controllerVM_instance | awk '{print $2}'")[1]
    if InstanceId:
        os.system("nova delete " + InstanceId)
        time.sleep(10)

    PolicyTargetId = commands.getstatusoutput(
        "gbp policy-target-list | grep nfp_controllerVM_instance"
        " | awk '{print $2}'")[1]
    if PolicyTargetId:
        os.system("gbp policy-target-delete " + PolicyTargetId)

    ImageId = commands.getstatusoutput(
        "glance image-list | grep nfp_controller | awk '{print $2}'")[1]
    if ImageId:
        os.system("glance image-delete " + ImageId)

    ServiceMGMTId = commands.getstatusoutput(
        "gbp group-list | grep '\ssvc_management_ptg\s'"
        " | awk '{print $2}'")[1]
    if ServiceMGMTId:
        SvcGroupId = commands.getstatusoutput(
            "gbp group-list | grep '\ssvc_management_ptg\s'"
            " | awk '{print $2}'")[1]
        l2policyId = commands.getstatusoutput(
            "gbp l2policy-list | grep '\ssvc_management_ptg\s'"
            " | awk '{print $2}'")[1]
        l3policyId = commands.getstatusoutput(
            "gbp l3policy-list | grep '\sdefault-nfp\s'"
            " | awk '{print $2}'")[1]
        os.system("gbp group-delete " + SvcGroupId)
        os.system("gbp l2policy-delete " + l2policyId)
        os.system("gbp l3policy-delete " + l3policyId)

    HeatId = commands.getstatusoutput(
        "heat stack-list | grep '\sgbp_services_stack\s'"
        " | awk '{print $2}'")[1]
    if HeatId:
        os.system("heat stack-delete gbp_services_stack -y")


def main():
    if args.configure_nfp:
        configure_nfp()
    elif args.build_controller_vm:
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
    elif args.configure_ext_net:
        if args.ext_net_name != '':
            configure_ext_net(args.ext_net_name)
        else:
            parser.print_help()
    elif args.clean_up_nfp:
        clean_up()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
