#!/bin/vbash
source /opt/vyatta/etc/functions/script-template

# set rules
set firewall all-ping 'enable'
set firewall broadcast-ping 'disable'
set firewall config-trap 'disable'
set firewall ipv6-receive-redirects 'disable'
set firewall ipv6-src-route 'disable'
set firewall ip-src-route 'disable'
set firewall log-martians 'enable'
set firewall receive-redirects 'disable'
set firewall send-redirects 'enable'
set firewall source-validation 'disable'
set firewall syn-cookies 'enable'
set firewall twa-hazards-protection 'disable'
set  'policy'
set protocols 'static'

# delete non-working repository
delete system package repository community
# Add squeeze repository for downloading dependent packages
set system package repository squeeze components 'main contrib non-free'
set system package repository squeeze distribution 'squeeze'
set system package repository squeeze url 'http://archive.debian.org/debian'
set system package repository squeeze-lts components 'main contrib non-free'
set system package repository squeeze-lts distribution 'squeeze-lts'
set system package repository squeeze-lts url 'http://archive.debian.org/debian'
# set local repo 
set system package repository vyos components '#'
set system package repository vyos distribution 'amd64/'
set system package repository vyos url 'http://192.168.122.1/vyos/'

# change password
set system login user vyos authentication plaintext-password $VYOS_PASSWORD
commit
save

# update the repo
sudo apt-get -o Acquire::Check-Valid-Until=false update
# install dependent packages
sudo apt-get -y install python-netifaces python-flask python-netaddr

# get vyos package
sudo apt-get -y --force-yes install vyos

set system task-scheduler task health-monitor executable path '/usr/share/vyos/config_server/interface_monitor.sh'
set system task-scheduler task health-monitor interval '5m'

# delete the local repo
delete system package repository vyos

# commit and save the above changes
commit
save
exit

# edit /etc/network/interfaces file as required by vyos agent
# make 'static' to all interfaces except eth0
sudo sed -i 's/inet dhcp/inet static/g' /etc/network/interfaces
sudo sed -i 's/eth0 inet static/eth0 inet dhcp/g' /etc/network/interfaces

# copy the missing pl files
sudo cp /opt/vyatta/sbin/vyatta-firewall-trap.pl /
sudo cp /opt/vyatta/sbin/valid_port_range.pl /
sudo cp /opt/vyatta/sbin/vyatta-firewall.pl /
sudo cp /opt/vyatta/sbin/vyatta-fw-global-state-policy.pl /
sudo cp /opt/vyatta/sbin/vyatta-ipset.pl /

# free up disk space
sudo rm -rf /var/lib/apt/lists
sudo apt-get clean
sudo apt-get autoclean
