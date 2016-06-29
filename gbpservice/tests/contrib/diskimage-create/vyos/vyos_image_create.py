import sys
import os
import json
import subprocess
import commands
import datetime
import requests


conf = []
cur_dir = ''

def parse_json(j_file):
    global conf

    with open(j_file) as json_data:
        config = json.load(json_data)
    return config


def update_vyos_repo():

    vyos_vendor_dir = ("%s/../../../../nfp/service_vendor_agents/vyos/" % cur_dir)
    service = 'agent'
    version = '2'
    release = '1'
    subprocess.call(['rm', '-rf',
                     "%s/%s/deb-packages" % (vyos_vendor_dir, service)])
    os.chdir(vyos_vendor_dir)
    ret = subprocess.call(['bash',
                           'build_vyos_deb.sh',
                           service,
                           version, release])

    if(ret):
        print "ERROR: Unable to generate vyos agent deb package"
        return 1

    subprocess.call(["rm", "-rf", "/var/www/html/vyos"])
    subprocess.call(["mkdir", "-p", "/var/www/html/vyos/amd64"])
    vyos_agent_deb = ("%s/%s/deb-packages/vyos-%s-%s.deb"
                         % (vyos_vendor_dir, service,
                            version, release))
    subprocess.call(["cp", vyos_agent_deb, "/var/www/html/vyos/amd64/"])

    # update repo Packages.gz
    os.chdir("/var/www/html/vyos")
    out = commands.getoutput("dpkg-scanpackages amd64 | gzip -9c > amd64/Packages.gz")
    print out

    return 0

def packer_build():

    os.chdir(cur_dir)
    os.environ['VYOS_PASSWORD'] = conf['packer']['vyos_pswd']

    # get the packer configuration
    try:
        conf_packer = parse_json("./packer.json")
    except Exception as e:
        print "ERROR: parsing ./packer.json file"
        print e
        return
    
    # packer expects VM size in MB
    conf_packer['builders'][0]['disk_size'] = conf['packer']['image_size'] * 1024
    # packer exptects new output dir name for each run, packer creates the dir
    # update VM output file name
    filepath = os.environ.get('ISO_IMAGE', '-1')
    iso = os.path.basename(filepath)

    # update the packer.json file
    with open('packer.json', 'w') as f:
        json.dump(conf_packer, f, sort_keys = True, indent = 4, ensure_ascii=False)

    print "\n#########################################################"
    print "Invoking packer build, this will take about 10mins......"
    print "#########################################################\n"
    # invoke packer build 
    ret = subprocess.call(["packer", "build", "packer.json"])
    if ret:
        print "ERROR: packer build failed"

    image_path = "%s/output/%s.qcow2" % (cur_dir, "vyos")
    print("Image location: %s" % image_path)
    with open("%s/../output/last_built_image_path" % cur_dir, "w") as f:
        f.write(image_path)
    f.close()

    return

def check_packer_tool():
    if(os.path.isfile("/usr/local/bin/packer")):
        return 0
   
    # get packer tool from website
    print "Downloading 'packer' tool"
    ret = subprocess.call(["wget", "https://releases.hashicorp.com/packer/0.10.1/packer_0.10.1_linux_amd64.zip"])
    if ret:
        print "ERROR: Unable to download packer tool"
        return 1
    # unzip the file and copy packer tool to specific place
    ret = subprocess.call(["unzip", "packer_0.10.1_linux_amd64.zip"])
    if ret:
        return 1
    ret = subprocess.call(["cp", "packer", "/usr/local/bin/"])
    if ret:
        return 1
    return 0

def get_vyos_iso():
    iso_path = os.environ['HOME'] + "/.cache/image-create/"
    iso_file = "vyos-1.1.7-amd64.iso"
    os.environ['ISO_IMAGE'] = iso_path + iso_file
    os.environ['ISO_MD5_SUM'] = commands.getoutput("md5sum %s" % (iso_path + iso_file)).split(' ')[0]
    if(os.path.isfile(iso_path + iso_file)):
        print "VyOS iso: %s exists locally" % (iso_path + iso_file)
        return 0
   
    # get the output dir
    if not os.path.isdir(iso_path):
        os.makedirs(iso_path)

    # download iso from internet
    os.chdir(iso_path)
    print "Downloading VyOS 1.1.7 ISO"
    iso_url = "http://packages.vyos.net/iso/release/1.1.7/vyos-1.1.7-amd64.iso"
    ret = subprocess.call(["wget", iso_url])
    if ret:
        return 1

    # get sha1sum for iso from web
    sha1sum_web = ''
    r = requests.get("http://packages.vyos.net/iso/release/1.1.7/sha1sums")
    sha1sums = r.content.splitlines()
    for sums in sha1sums:
        if(sums.find(iso_file)) > 0:
            sha1sum_web = sums.split(' ')[0]

    # calculate the sha1 of downloaded file
    sha1sum_local = commands.getoutput("sha1sum %s" % (iso_path + iso_file)).split(' ')[0]

    if not sha1sum_web == sha1sum_local:
        print "Downloaded iso file is corrupt, exiting now..."
        return 1
    os.environ['ISO_MD5_SUM'] = commands.getoutput("md5sum %s" % (iso_path + iso_file)).split(' ')[0]     

    return 0



if __name__ == "__main__":

    if os.geteuid():
        sys.exit("ERROR: Script should be run as sudo/root")
    if len(sys.argv) != 2:
        print "ERROR: Invalid Usage"
        print "Usage:\n\t%s <json config file>" % sys.argv[0]
        print "\twhere: <json config file> contains all the configuration"
        exit()
    # save PWD
    cur_dir = os.path.dirname(__file__)
    cur_dir = os.path.realpath(cur_dir)
    if not cur_dir:
        # if script is executed from current dir, get abs path
        cur_dir = os.path.realpath('./')

    # parse args from json file
    try:
        conf = parse_json(sys.argv[1])
    except Exception as e:
        print "ERROR parsing json file"
        print e
        exit()

    if(check_packer_tool()):
        print "ERROR: Failed to get packer tool"
        exit()

    if(get_vyos_iso()):
        print "ERROR: Unable to get vyos-1.1.7-amd64.iso file"
        exit()

    if(update_vyos_repo()):
        exit()

    packer_build()
