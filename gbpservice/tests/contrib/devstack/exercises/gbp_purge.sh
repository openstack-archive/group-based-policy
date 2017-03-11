#!/usr/bin/env bash

# **gbp_purge.sh**

# Sanity check that gbp started if enabled

echo "*********************************************************************"
echo "Begin DevStack Exercise: $0"
echo "*********************************************************************"

# Settings
# ========

source functions-gbp

# This script exits on an error so that errors don't compound and you see
# only the first error that occurred.
set -o errexit

# Keep track of the current directory
EXERCISE_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $EXERCISE_DIR/..; pwd)

# Import common functions
source $TOP_DIR/functions

# Import configuration
source $TOP_DIR/openrc

# Import exercise configuration
source $TOP_DIR/exerciserc

source $TOP_DIR/openrc demo demo

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following allowing as the install occurs.
set -o xtrace

# Create servicechain related policies
gbp service-profile-create --vendor heat_based_node_driver --insertion-mode l3 --servicetype FIREWALL fw-profile
gbp servicechain-node-create firewall-node --template-file $TOP_DIR/gbp-templates/firewall-lb-servicechain/fw.template --service-profile fw-profile
gbp servicechain-spec-create firewall-spec --description spec --nodes "firewall-node"

# NSP creation
gbp network-service-policy-create --network-service-params type=ip_single,name=vip_ip,value=self_subnet vip_ip_policy

# Create action that can used in several rules
gbp policy-action-create allow_action --action-type allow
gbp policy-action-create redirect --action-type redirect --action-value firewall-spec

# Create ICMP rule
gbp policy-classifier-create icmp-traffic --protocol icmp --direction bi
gbp policy-rule-create ping-policy-rule --classifier icmp-traffic --actions allow_action
#gbp policy-rule-create ping-policy-rule --classifier icmp-traffic --actions redirect

# ICMP policy-rule-set
gbp policy-rule-set-create icmp-policy-rule-set --policy-rules ping-policy-rule

# ====== PROJECT OPERATION ======
# PTGs creation
gbp group-create --provided-policy-rule-sets "icmp-policy-rule-set" --consumed-policy-rule-sets "icmp-policy-rule-set" --network-service-policy vip_ip_policy web
gbp group-create web1

# PT creation
gbp policy-target-create web-pt-1 --policy-target-group web

# create external network with admin priviledge
source $TOP_DIR/openrc admin admin
EXT_NET_ID=$(neutron net-create mgmt_out --router:external=True --shared | grep ' id ' | awk '{print $4}')
EXT_SUBNET_ID=$(neutron subnet-create --ip_version 4 --gateway 172.16.73.1 --name public-subnet $EXT_NET_ID 172.16.73.0/24 | grep ' id ' | awk '{print $4}')
openstack project list
DEMO_PROJECT_ID=$(openstack project show demo | grep id | awk '{print $4}')

source $TOP_DIR/openrc demo demo

# ES creation
gbp external-segment-create --ip-version 4 --external-route destination=0.0.0.0/0,nexthop=172.16.73.1 --subnet_id=$EXT_SUBNET_ID  --cidr 50.50.50.0/24 mgmt_out

gbp l3policy-update --external-segment mgmt_out default

# Nat pool creation
gbp nat-pool-create --ip-version 4 --ip-pool 60.60.60.0/24 --external-segment mgmt_out ext_nat_pool

# External policy creation
gbp external-policy-create --external-segment mgmt_out --provided-policy-rule-sets "icmp-policy-rule-set" --consumed-policy-rule-sets "icmp-policy-rule-set" ext_pol

# purge all the resources
gbp purge $DEMO_PROJECT_ID

PURGE_OUTPUT=$(gbp purge $DEMO_PROJECT_ID | grep 'Tenant has no supported resources')
die_if_not_set $LINENO PURGE_OUTPUT "Failure purging GBP resources"

# delete the neutron resources too
source $TOP_DIR/openrc admin admin
neutron subnet-delete public-subnet
neutron net-delete mgmt_out

check_residual_resources demo demo
check_residual_resources admin admin

set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End DevStack Exercise: $0"
echo "*********************************************************************"
